"""Unit tests for AutoPatch ValidationAgent and its decision engine."""

import os
import shutil
import tempfile
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.agents.validation_agent import ValidationAgent
from backend.database.database import Base
from backend.database.models import (
    PatchAttemptModel,
    RiskAssessmentModel,
    ValidationResultModel,
    VulnerabilityModel,
    WorkflowModel,
)
from backend.models.patch import PatchStatus
from backend.models.validation import ValidationResult, ValidationStatus
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
)
from backend.tools.test_runner import TestResult, TestRunner


@pytest.fixture
def sqlite_session():
    """In-memory SQLite session for ValidationAgent database testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def temp_repo():
    """Create a temporary Python project on disk with clean syntax and a test."""
    temp_dir = tempfile.mkdtemp(prefix="autopatch_test_repo_")
    repo = Path(temp_dir)

    # Simple target code
    app_file = repo / "app.py"
    app_file.write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")

    # Simple test file
    test_file = repo / "test_app.py"
    test_file.write_text("from app import run\n\ndef test_run():\n    assert run('ok') == 'ok'\n", encoding="utf-8")

    yield repo

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def sample_finding():
    """Generate a sample normalized VulnerabilityFinding."""
    return VulnerabilityFinding(
        id="vuln-cmd-001",
        workflow_id="wf-test-1",
        tool="bandit",
        rule_id="B602",
        type="Subprocess Popened With Shell",
        cwe="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_start=1,
        line_end=2,
        code_snippet="return cmd",
        description="Subprocess call with shell=True",
        status=VulnerabilityStatus.PRIORITIZED,
    )


def test_successful_validation(temp_repo, sample_finding):
    """Verify clean validation pass when patch applies, syntax passes, tests pass, and vuln resolves."""
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return str(cmd).strip()
"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(
        success=True,
        exit_code=0,
        command=["pytest"],
        stdout="1 passed in 0.01s",
        duration=0.1,
        tests_passed=1,
    )

    mock_scanner = MagicMock()
    # Re-scan finds zero vulnerabilities
    mock_scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(
        test_runner=mock_runner,
        scanning_agent=mock_scanner,
    )

    result = agent.execute_validation(
        patch_id="patch-123",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        workflow_id="wf-test-1",
        persist=False,
    )

    assert result.status == ValidationStatus.PASSED
    assert result.patch_applied is True
    assert result.syntax_check_passed is True
    assert result.tests_passed is True
    assert result.original_vulnerability_resolved is True
    assert result.regression_detected is False
    assert result.failure_reason is None


def test_patch_application_failure(temp_repo, sample_finding):
    """Verify validation fails early if patch application rejects the diff."""
    # Malformed diff targeting nonexistent file
    diff = """--- a/nonexistent.py
+++ b/nonexistent.py
@@ -1,1 +1,1 @@
-old
+new
"""

    agent = ValidationAgent()
    result = agent.execute_validation(
        patch_id="patch-bad",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )

    assert result.status == ValidationStatus.FAILED
    assert result.patch_applied is False
    assert "Patch application failed" in (result.failure_reason or "")


def test_syntax_failure(temp_repo, sample_finding):
    """Verify validation fails if patch introduces Python syntax errors."""
    broken_syntax_diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    def def def broken syntax:::
"""

    agent = ValidationAgent()
    result = agent.execute_validation(
        patch_id="patch-syntax-err",
        vulnerability=sample_finding,
        unified_diff=broken_syntax_diff,
        repository_path=temp_repo,
        persist=False,
    )

    assert result.status == ValidationStatus.FAILED
    assert result.patch_applied is True
    assert result.syntax_check_passed is False
    assert "Syntax check failed" in (result.failure_reason or "") or "SyntaxError" in (result.failure_reason or "")


def test_test_suite_failure(temp_repo, sample_finding):
    """Verify validation fails when project test runner reports failures."""
    valid_diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return "wrong_return_value"
"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(
        success=False,
        exit_code=1,
        command=["pytest"],
        stdout="1 failed in 0.05s",
        duration=0.2,
        tests_failed=1,
        error_message="AssertionError in test_app.py",
    )

    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    result = agent.execute_validation(
        patch_id="patch-test-fail",
        vulnerability=sample_finding,
        unified_diff=valid_diff,
        repository_path=temp_repo,
        persist=False,
    )

    assert result.status == ValidationStatus.FAILED
    assert result.patch_applied is True
    assert result.syntax_check_passed is True
    assert result.tests_passed is False
    assert result.regression_detected is True
    assert "AssertionError" in (result.failure_reason or "")


def test_scanner_failure_handling(temp_repo, sample_finding):
    """Verify scanner failure is NOT interpreted as zero vulnerabilities."""
    valid_diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return str(cmd)
"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1)

    mock_scanner = MagicMock()
    # Scanners crashed/failed
    mock_scanner.scan.return_value = ([], {"scan_status": "FAILED", "errors": ["Bandit crashed", "Semgrep timeout"]})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    result = agent.execute_validation(
        patch_id="patch-scanner-fail",
        vulnerability=sample_finding,
        unified_diff=valid_diff,
        repository_path=temp_repo,
        persist=False,
    )

    assert result.status == ValidationStatus.ERROR
    assert result.original_vulnerability_resolved is False
    assert result.security_scan_passed is False
    assert "Security re-scan failed" in (result.failure_reason or "")


def test_unresolved_original_vulnerability(temp_repo, sample_finding):
    """Verify validation fails if the original finding is still detected in re-scan."""
    valid_diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return cmd
"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1)

    mock_scanner = MagicMock()
    # Re-scan reports same finding still present
    mock_scanner.scan.return_value = ([sample_finding], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    result = agent.execute_validation(
        patch_id="patch-unresolved",
        vulnerability=sample_finding,
        unified_diff=valid_diff,
        repository_path=temp_repo,
        persist=False,
    )

    assert result.status == ValidationStatus.FAILED
    assert result.original_vulnerability_resolved is False
    assert "still detected" in (result.failure_reason or "")


def test_new_vulnerability_introduced(temp_repo, sample_finding):
    """Verify validation fails if patch introduces a brand-new security vulnerability."""
    valid_diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    import pickle; return pickle.loads(cmd)
"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1)

    new_finding = VulnerabilityFinding(
        id="vuln-pickle-new",
        workflow_id="wf-test-1",
        tool="bandit",
        rule_id="B301",
        type="Pickle Insecure Deserialization",
        cwe="CWE-502",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_start=2,
        line_end=2,
        description="Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data",
    )

    mock_scanner = MagicMock()
    # Original finding is gone, but new finding is present
    mock_scanner.scan.return_value = ([new_finding], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    result = agent.execute_validation(
        patch_id="patch-new-vuln",
        vulnerability=sample_finding,
        unified_diff=valid_diff,
        repository_path=temp_repo,
        persist=False,
    )

    assert result.status == ValidationStatus.FAILED
    assert result.original_vulnerability_resolved is True
    assert result.regression_detected is True
    assert result.new_findings_count == 1
    assert "new security finding" in (result.failure_reason or "")


def test_test_runner_timeout(temp_repo, sample_finding):
    """Verify handling when test execution times out."""
    valid_diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return str(cmd)
"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(
        success=False,
        exit_code=-1,
        command=["pytest"],
        timed_out=True,
        duration=30.0,
        error_message="Test runner timed out after 30.0s.",
    )

    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    result = agent.execute_validation(
        patch_id="patch-timeout",
        vulnerability=sample_finding,
        unified_diff=valid_diff,
        repository_path=temp_repo,
        persist=False,
    )

    assert result.status == ValidationStatus.FAILED
    assert result.regression_detected is True
    assert "timed out" in (result.failure_reason or "")


def test_missing_patch_attempt(sqlite_session):
    """Verify ValueError is raised if validate_patch is called with nonexistent patch_id."""
    agent = ValidationAgent()
    with pytest.raises(ValueError, match="Patch attempt 'nonexistent-patch' not found."):
        agent.validate_patch(
            patch_id="nonexistent-patch",
            persist=True,
            db_session=sqlite_session,
        )


def test_missing_risk_assessment(sqlite_session, temp_repo):
    """Verify ValueError is raised if patch vulnerability has no risk assessment."""
    wf = WorkflowModel(id="wf-test-no-risk", repository_path=str(temp_repo))
    vuln = VulnerabilityModel(
        id="vuln-no-risk",
        workflow_id="wf-test-no-risk",
        tool="bandit",
        rule_id="B602",
        type="Command Injection",
        file_path="app.py",
        severity="HIGH",
        description="Subprocess call without shell=False",
    )
    patch_attempt = PatchAttemptModel(
        id="patch-no-risk",
        workflow_id="wf-test-no-risk",
        vulnerability_id="vuln-no-risk",
        patch_content="dummy",
        status=PatchStatus.GENERATED.value,
    )
    sqlite_session.add_all([wf, vuln, patch_attempt])
    sqlite_session.commit()

    agent = ValidationAgent()
    with pytest.raises(ValueError, match="No risk assessment found for vulnerability 'vuln-no-risk'."):
        agent.validate_patch(
            patch_id="patch-no-risk",
            persist=True,
            db_session=sqlite_session,
        )


def test_database_persistence_and_patch_status_update(sqlite_session, temp_repo, sample_finding):
    """Verify full DB persistence, status transitions, and ValidationResultModel storage."""
    # Setup full DB records
    wf = WorkflowModel(id="wf-full", repository_path=str(temp_repo))
    vuln = VulnerabilityModel(
        id=sample_finding.id,
        workflow_id="wf-full",
        tool=sample_finding.tool,
        rule_id=sample_finding.rule_id,
        type=sample_finding.type,
        file_path=sample_finding.file_path,
        severity="HIGH",
        description=sample_finding.description,
        status=VulnerabilityStatus.PRIORITIZED.value,
    )
    risk = RiskAssessmentModel(
        id="risk-full",
        vulnerability_id=sample_finding.id,
        priority="CRITICAL",
        risk_score=9.5,
        severity="HIGH",
        exploitability=0.8,
        business_impact=0.9,
        reasoning="Critical remote command execution risk.",
    )
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return str(cmd).strip()
"""
    patch_attempt = PatchAttemptModel(
        id="patch-full",
        workflow_id="wf-full",
        vulnerability_id=sample_finding.id,
        patch_content=diff,
        status=PatchStatus.GENERATED.value,
    )
    sqlite_session.add_all([wf, vuln, risk, patch_attempt])
    sqlite_session.commit()

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1, tests_passed=1)

    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    val_result = agent.validate_patch(
        patch_id="patch-full",
        persist=True,
        db_session=sqlite_session,
    )

    assert val_result.status == ValidationStatus.PASSED

    # Verify PatchAttemptModel was updated to VALIDATED
    refreshed_patch = sqlite_session.query(PatchAttemptModel).filter(PatchAttemptModel.id == "patch-full").first()
    assert refreshed_patch.status == PatchStatus.READY_FOR_REVIEW.value

    # Verify VulnerabilityModel was transitioned to VALIDATED
    refreshed_vuln = sqlite_session.query(VulnerabilityModel).filter(VulnerabilityModel.id == sample_finding.id).first()
    assert refreshed_vuln.status == VulnerabilityStatus.VALIDATED.value

    # Verify ValidationResultModel was persisted
    val_records = sqlite_session.query(ValidationResultModel).filter(
        ValidationResultModel.patch_attempt_id == "patch-full"
    ).all()
    assert len(val_records) == 1
    assert val_records[0].status == "PASSED"
    assert val_records[0].patch_applied is True
    assert val_records[0].tests_passed is True
    assert val_records[0].original_vulnerability_resolved is True
