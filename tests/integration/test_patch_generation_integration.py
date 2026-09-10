"""End-to-End Integration tests for the complete AutoPatch Pipeline up to Patch Generation:

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
Unified Diff Synthesis & Safety Verification
    ↓
Patch Attempt Persistence

Strictly verifies that the original repository files remain 100% untouched on disk.
"""

import hashlib
import os
from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.agents.scanning_agent import ScanningAgent
from backend.database.models import PatchAttemptModel
from backend.models.patch import PatchStatus
from backend.models.risk_assessment import PriorityLevel
from backend.services.llm.mock_provider import MockLLMProvider
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


def test_full_pipeline_to_patch_generation_end_to_end(
    vulnerable_repo_path: Path,
    db_session: Session,
):
    """
    Execute full pipeline and verify candidate patch generation with strict repository immutability.
    """
    # 0. Snapshot repository hashes prior to run
    initial_hashes = _compute_directory_hashes(vulnerable_repo_path)
    assert len(initial_hashes) > 0

    # 1. Scanning Agent
    scanner = ScanningAgent()
    findings, metadata = scanner.scan(
        vulnerable_repo_path,
        persist=True,
        db_session=db_session,
    )
    workflow_id = metadata["workflow_id"]
    assert len(findings) >= 2

    # 2. Risk Assessment Agent
    risk_agent = RiskAssessmentAgent()
    prioritized = risk_agent.assess_workflow(
        workflow_id=workflow_id,
        persist=True,
        db_session=db_session,
    )
    assert len(prioritized) == len(findings)

    # Pick top prioritized finding (Critical / High)
    top_prioritized = prioritized[0]
    top_vuln = top_prioritized.vulnerability
    top_risk = top_prioritized.risk_assessment

    assert top_risk.priority in (PriorityLevel.CRITICAL, PriorityLevel.HIGH)

    # 3. Repository Context Service
    context_service = RepositoryContextService(context_lines_before=10, context_lines_after=10)
    context = context_service.build_context(
        repository_root=str(vulnerable_repo_path),
        finding=top_vuln,
    )
    assert context.surrounding_code is not None
    assert len(context.surrounding_code) > 0

    # 4. Patch Generation Agent with provider-independent mock LLM
    mock_provider = MockLLMProvider()
    llm_service = LLMService(provider=mock_provider)
    patch_agent = PatchGenerationAgent(
        llm_service=llm_service,
        repository_context_service=context_service,
    )

    patch_result = patch_agent.generate_patch(
        vulnerability=top_vuln,
        risk_assessment=top_risk,
        repository_context=context,
        attempt_number=1,
        persist=True,
        db_session=db_session,
    )

    # 5. Verify Patch Result
    assert patch_result.status == PatchStatus.GENERATED
    assert patch_result.vulnerability_id == top_vuln.id
    assert patch_result.attempt_number == 1
    assert patch_result.unified_diff is not None
    assert len(patch_result.unified_diff) > 0
    assert "--- a/" in patch_result.unified_diff
    assert "+++ b/" in patch_result.unified_diff
    assert len(patch_result.changed_files) >= 1
    assert patch_result.confidence > 0.0

    # 6. Verify Database Persistence of Patch Attempt
    db_attempt = db_session.query(PatchAttemptModel).filter(
        PatchAttemptModel.vulnerability_id == top_vuln.id
    ).first()

    assert db_attempt is not None
    assert db_attempt.id == patch_result.id
    assert db_attempt.status == "GENERATED"
    assert db_attempt.attempt_number == 1
    assert db_attempt.patch_content == patch_result.unified_diff
    assert db_attempt.explanation is not None

    # 7. MANDATORY IMMUTABILITY VERIFICATION:
    # Verify that not a single file on disk in the original repo was modified
    final_hashes = _compute_directory_hashes(vulnerable_repo_path)
    assert initial_hashes == final_hashes, "Repository on disk was modified during patch generation!"
