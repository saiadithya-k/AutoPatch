"""End-to-End Integration tests for Phase 6: Validation Agent & Tooling.

Pipeline flow:
Vulnerable Repository
    ↓
Scanning Agent
    ↓
Risk Assessment Agent
    ↓
Repository Context Service
    ↓
Patch Generation Agent (Mock LLM)
    ↓
Validation Agent (Isolated Workspace)
    ↓
Validation Result Persistence

Strictly verifies:
- Candidates apply cleanly, pass syntax, tests, and security re-scans.
- Negative demos accurately produce FAILED statuses with diagnostic reasons.
- The original repository on disk remains 100% untouched (SHA-256 verified).
"""

import hashlib
import os
import sys
from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.agents.scanning_agent import ScanningAgent
from backend.agents.validation_agent import ValidationAgent
from backend.database.models import (
    PatchAttemptModel,
    RiskAssessmentModel,
    ValidationResultModel,
    VulnerabilityModel,
)
from backend.models.patch import PatchStatus
from backend.models.risk_assessment import PriorityLevel
from backend.models.validation import ValidationStatus
from backend.models.vulnerability import VulnerabilityStatus
from backend.services.llm.mock_provider import MockLLMProvider
from backend.services.llm.schemas import LLMCodeChange, LLMPatchGeneration
from backend.services.llm.service import LLMService
from backend.services.repository_context import RepositoryContextService


def _compute_directory_hashes(directory: Path) -> dict[str, str]:
    """Calculate sha256 checksum for each file in directory to ensure immutability."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix in (".py", ".txt", ".md", ".json", ".sql"):
                file_hashes[str(fpath.relative_to(directory))] = hashlib.sha256(
                    fpath.read_bytes()
                ).hexdigest()
    return file_hashes


def test_full_pipeline_validation_real_demo_patch(
    vulnerable_repo_path: Path,
    db_session: Session,
):
    """
    Execute full pipeline from Scan to Validation on vulnerable demo project.
    Verifies that a safe patch for command injection succeeds across all criteria
    and leaves the original repository completely unmodified.
    """
    # 0. Checksum baseline
    initial_hashes = _compute_directory_hashes(vulnerable_repo_path)
    assert len(initial_hashes) > 0

    # 1. Scanning Agent
    scanner = ScanningAgent()
    findings, scan_metadata = scanner.scan(
        vulnerable_repo_path,
        persist=True,
        db_session=db_session,
    )
    workflow_id = scan_metadata["workflow_id"]
    assert len(findings) >= 2

    # 2. Risk Assessment Agent
    risk_agent = RiskAssessmentAgent()
    prioritized = risk_agent.assess_workflow(
        workflow_id=workflow_id,
        persist=True,
        db_session=db_session,
    )
    assert len(prioritized) == len(findings)

    # Locate the Command Injection finding in app.py (B605 or CWE-78)
    cmd_findings = [
        p for p in prioritized
        if p.vulnerability.file_path == "app.py"
        and (p.vulnerability.rule_id == "B605" or "Command" in p.vulnerability.type or "Shell" in p.vulnerability.type)
    ]
    assert len(cmd_findings) >= 1
    target_pair = cmd_findings[0]
    target_vuln = target_pair.vulnerability
    target_risk = target_pair.risk_assessment

    # 3. Repository Context Service
    context_service = RepositoryContextService(context_lines_before=10, context_lines_after=10)
    context = context_service.build_context(
        repository_root=str(vulnerable_repo_path),
        finding=target_vuln,
    )
    assert context.surrounding_code is not None

    # 4. Preserve the diagnostic's output and success code without shell execution.
    # In app.py: replace `command = f"echo Running diagnostic for host {target_host}"\n    return os.system(command)`
    safe_replacement = (
        '    print(f"Running diagnostic for host {target_host}")\n'
        '    return 0'
    )
    mock_llm_payload = LLMPatchGeneration(
        explanation="Print the diagnostic directly and preserve its success return code.",
        changes=[
            LLMCodeChange(
                file_path="app.py",
                start_line=14,
                end_line=15,
                original_code='    command = f"echo Running diagnostic for host {target_host}"\n    return os.system(command)',
                replacement_code=safe_replacement,
            )
        ],
        unified_diff="",  # Unified diff will be synthesized cleanly by PatchGenerationAgent
        assumptions=["The diagnostic only prints a message and returns success"],
        tests_to_run=["test_app.py"],
    )

    mock_provider = MockLLMProvider(canned_parsed=mock_llm_payload)
    llm_service = LLMService(provider=mock_provider)
    patch_agent = PatchGenerationAgent(
        llm_service=llm_service,
        repository_context_service=context_service,
    )

    patch_result = patch_agent.generate_patch(
        vulnerability=target_vuln,
        risk_assessment=target_risk,
        repository_context=context,
        attempt_number=1,
        persist=True,
        db_session=db_session,
    )

    assert patch_result.status == PatchStatus.GENERATED
    assert patch_result.unified_diff is not None
    assert "--- a/app.py" in patch_result.unified_diff

    # 5. Validation Agent execution in isolated workspace
    val_agent = ValidationAgent()
    val_result = val_agent.validate_patch(
        patch_id=patch_result.id,
        persist=True,
        db_session=db_session,
    )

    # 6. Verify Validation Criteria (All conditions met)
    assert val_result.status == ValidationStatus.PASSED, (
        f"Failed reason: {val_result.failure_reason}\n"
        f"New findings:\n{val_result.new_findings}\n"
        f"Test stdout:\n{val_result.test_stdout}\n"
        f"Test stderr:\n{val_result.test_stderr}\n"
        f"Logs: {val_result.validation_logs}"
    )
    assert val_result.patch_applied is True
    assert val_result.syntax_check_passed is True
    assert val_result.tests_passed is True
    assert val_result.original_vulnerability_resolved is True
    assert val_result.security_scan_passed is True
    assert val_result.regression_detected is False
    assert val_result.failure_reason is None

    # 7. Verify Database Persistence and Lifecycle Transitions
    db_patch = db_session.query(PatchAttemptModel).filter(PatchAttemptModel.id == patch_result.id).first()
    assert db_patch is not None
    assert db_patch.status == PatchStatus.READY_FOR_REVIEW.value

    db_vuln = db_session.query(VulnerabilityModel).filter(VulnerabilityModel.id == target_vuln.id).first()
    assert db_vuln is not None
    assert db_vuln.status == VulnerabilityStatus.VALIDATED.value

    db_val = db_session.query(ValidationResultModel).filter(
        ValidationResultModel.patch_attempt_id == patch_result.id
    ).first()
    assert db_val is not None
    assert db_val.status == "PASSED"
    assert db_val.patch_applied is True
    assert db_val.tests_passed is True
    assert db_val.original_vulnerability_resolved is True

    # 8. MANDATORY REPOSITORY IMMUTABILITY VERIFICATION
    final_hashes = _compute_directory_hashes(vulnerable_repo_path)
    assert initial_hashes == final_hashes, "CRITICAL: Vulnerable repository files on disk were modified!"


def test_validation_negative_demo_syntax_error(
    vulnerable_repo_path: Path,
    db_session: Session,
):
    """
    Verify validation fails cleanly when a candidate patch introduces a Python syntax error.
    """
    initial_hashes = _compute_directory_hashes(vulnerable_repo_path)

    # Setup workflow & vulnerability
    scanner = ScanningAgent()
    findings, scan_meta = scanner.scan(vulnerable_repo_path, persist=True, db_session=db_session)
    wf_id = scan_meta["workflow_id"]

    risk_agent = RiskAssessmentAgent()
    prioritized = risk_agent.assess_workflow(workflow_id=wf_id, persist=True, db_session=db_session)
    target = prioritized[0]

    # Malformed patch introducing syntax error
    broken_diff = """--- a/app.py
+++ b/app.py
@@ -14,2 +14,2 @@
-    command = f"echo Running diagnostic for host {target_host}"
-    return os.system(command)
+    def broken syntax error ::: :::
+    return
"""

    bad_patch = PatchAttemptModel(
        id="patch-bad-syntax",
        workflow_id=wf_id,
        vulnerability_id=target.vulnerability.id,
        patch_content=broken_diff,
        status=PatchStatus.GENERATED.value,
        attempt_number=1,
    )
    db_session.add(bad_patch)
    db_session.commit()

    val_agent = ValidationAgent()
    val_result = val_agent.validate_patch(
        patch_id="patch-bad-syntax",
        persist=True,
        db_session=db_session,
    )

    assert val_result.status == ValidationStatus.FAILED
    assert val_result.patch_applied is True
    assert val_result.syntax_check_passed is False
    assert "Syntax check failed" in (val_result.failure_reason or "") or "SyntaxError" in (val_result.failure_reason or "")

    # Patch attempt marked as FAILED_VALIDATION
    refreshed_patch = db_session.query(PatchAttemptModel).filter(PatchAttemptModel.id == "patch-bad-syntax").first()
    assert refreshed_patch.status == PatchStatus.FAILED_VALIDATION.value

    # Immutability
    final_hashes = _compute_directory_hashes(vulnerable_repo_path)
    assert initial_hashes == final_hashes


def test_validation_negative_demo_test_failure(
    vulnerable_repo_path: Path,
    db_session: Session,
):
    """
    Verify validation fails cleanly when candidate patch causes project tests to fail.
    """
    initial_hashes = _compute_directory_hashes(vulnerable_repo_path)

    scanner = ScanningAgent()
    findings, scan_meta = scanner.scan(vulnerable_repo_path, persist=True, db_session=db_session)
    wf_id = scan_meta["workflow_id"]

    risk_agent = RiskAssessmentAgent()
    prioritized = risk_agent.assess_workflow(workflow_id=wf_id, persist=True, db_session=db_session)
    target = prioritized[0]

    # Patch that compiles cleanly but causes test_execute_system_diagnostic to fail (returns 99 instead of 0)
    failing_diff = """--- a/app.py
+++ b/app.py
@@ -14,2 +14,1 @@
-    command = f"echo Running diagnostic for host {target_host}"
-    return os.system(command)
+    return 99
"""

    failing_patch = PatchAttemptModel(
        id="patch-failing-test",
        workflow_id=wf_id,
        vulnerability_id=target.vulnerability.id,
        patch_content=failing_diff,
        status=PatchStatus.GENERATED.value,
        attempt_number=1,
    )
    db_session.add(failing_patch)
    db_session.commit()

    val_agent = ValidationAgent()
    val_result = val_agent.validate_patch(
        patch_id="patch-failing-test",
        persist=True,
        db_session=db_session,
    )

    assert val_result.status == ValidationStatus.FAILED
    assert val_result.patch_applied is True
    assert val_result.syntax_check_passed is True
    assert val_result.tests_passed is False
    assert val_result.regression_detected is True

    # Immutability
    final_hashes = _compute_directory_hashes(vulnerable_repo_path)
    assert initial_hashes == final_hashes


def test_validation_negative_demo_unresolved_vulnerability(
    vulnerable_repo_path: Path,
    db_session: Session,
):
    """
    Verify validation fails when candidate patch applies cleanly and passes tests
    but leaves the original vulnerability unresolved during security re-scan.
    """
    initial_hashes = _compute_directory_hashes(vulnerable_repo_path)

    scanner = ScanningAgent()
    findings, scan_meta = scanner.scan(vulnerable_repo_path, persist=True, db_session=db_session)
    wf_id = scan_meta["workflow_id"]

    risk_agent = RiskAssessmentAgent()
    prioritized = risk_agent.assess_workflow(workflow_id=wf_id, persist=True, db_session=db_session)
    cmd_findings = [
        p for p in prioritized
        if p.vulnerability.file_path == "app.py"
        and (p.vulnerability.rule_id == "B605" or "Command" in p.vulnerability.type or "Shell" in p.vulnerability.type)
    ]
    target = cmd_findings[0]

    # Patch that modifies comments and variable name but preserves unsafe os.system call
    unresolved_diff = """--- a/app.py
+++ b/app.py
@@ -14,2 +14,3 @@
-    command = f"echo Running diagnostic for host {target_host}"
-    return os.system(command)
+    # Diagnostic run with modified variable name
+    cmd_str = f"echo Running diagnostic for host {target_host}"
+    return os.system(cmd_str)
"""

    unresolved_patch = PatchAttemptModel(
        id="patch-unresolved-vuln",
        workflow_id=wf_id,
        vulnerability_id=target.vulnerability.id,
        patch_content=unresolved_diff,
        status=PatchStatus.GENERATED.value,
        attempt_number=1,
    )
    db_session.add(unresolved_patch)
    db_session.commit()

    val_agent = ValidationAgent()
    val_result = val_agent.validate_patch(
        patch_id="patch-unresolved-vuln",
        persist=True,
        db_session=db_session,
    )

    assert val_result.status == ValidationStatus.FAILED
    assert val_result.patch_applied is True
    assert val_result.syntax_check_passed is True
    assert val_result.tests_passed is True
    assert val_result.original_vulnerability_resolved is False
    assert "still detected" in (val_result.failure_reason or "")

    # Status check
    refreshed_patch = db_session.query(PatchAttemptModel).filter(PatchAttemptModel.id == "patch-unresolved-vuln").first()
    assert refreshed_patch.status == PatchStatus.FAILED_VALIDATION.value

    # Immutability check
    final_hashes = _compute_directory_hashes(vulnerable_repo_path)
    assert initial_hashes == final_hashes

