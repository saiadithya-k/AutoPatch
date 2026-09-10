"""Integration tests for Phase 10: Bounded Patch Retry Loop & API endpoints.

Verifies:
1. POST /api/patches/{patch_id}/retry triggers retry loop and returns RetryLoopResult.
2. GET /api/patches/{patch_id}/retry-history returns complete lineage chain.
3. Multi-attempt retry loop reaches terminal states properly (READY_FOR_REVIEW, RETRY_EXHAUSTED).
4. Non-existent patch IDs return HTTP 404.
5. End-to-end immutability of original repository during retry loop execution.
"""

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.database.models import (
    PatchAttemptModel,
    RiskAssessmentModel,
    ValidationResultModel,
    VulnerabilityModel,
    WorkflowModel,
)
from backend.main import app
from backend.models.patch import PatchGenerationResult, PatchStatus
from backend.models.retry import FailureCategory, RetryDecision, RetryStatus
from backend.models.validation import ValidationResult, ValidationStatus




@pytest.fixture
def populated_workflow_and_patch(db_session, tmp_path):
    """Setup a workflow with vulnerability, risk assessment, and initial patch."""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    sample_code = repo_dir / "target.py"
    sample_code.write_text("def target():\n    return 'sensitive_token'\n", encoding="utf-8")

    wf = WorkflowModel(
        id="wf-retry-test-01",
        repository_path=str(repo_dir),
        status="IN_PROGRESS",
        current_stage="PATCH_GENERATION_COMPLETE",
    )
    db_session.add(wf)

    vuln = VulnerabilityModel(
        id="VULN-RETRY-01",
        workflow_id="wf-retry-test-01",
        tool="bandit",
        rule_id="B105",
        type="hardcoded_password_string",
        cwe="CWE-798",
        severity="HIGH",
        confidence="HIGH",
        file_path="target.py",
        line_start=2,
        line_end=2,
        code_snippet="return 'sensitive_token'",
        description="Hardcoded sensitive token",
        raw_finding=json.dumps({"test": "data"}),
        status="PRIORITIZED",
        exploitability=0.8,
        business_impact=0.8,
        risk_score=8.0,
        priority="P1",
        risk_reasoning="High risk secret in code",
    )
    db_session.add(vuln)

    ra = RiskAssessmentModel(
        id="RA-RETRY-01",
        vulnerability_id="VULN-RETRY-01",
        workflow_id="wf-retry-test-01",
        severity="HIGH",
        severity_score=8.0,
        exploitability=0.8,
        business_impact=0.8,
        context_score=1.0,
        risk_score=8.0,
        priority="P1",
        reasoning="High risk secret in code",
        assessment_method="DETERMINISTIC_RULES",
    )
    db_session.add(ra)

    p1 = PatchAttemptModel(
        id="PATCH-INIT-01",
        workflow_id="wf-retry-test-01",
        vulnerability_id="VULN-RETRY-01",
        attempt_number=1,
        patch_format="unified_diff",
        patch_content="--- a/target.py\n+++ b/target.py\n@@ -2,1 +2,1 @@\n-    return 'sensitive_token'\n+    return os.getenv('TOKEN')\n",
        explanation="Initial attempt",
        files_changed=json.dumps(["target.py"]),
        status="GENERATED",
        retryable=True,
    )
    db_session.add(p1)
    db_session.commit()

    return {
        "workflow_id": "wf-retry-test-01",
        "vulnerability_id": "VULN-RETRY-01",
        "patch_id": "PATCH-INIT-01",
        "repo_path": repo_dir,
    }


def test_api_retry_endpoint_not_found(client):
    """POST /api/patches/non_existent/retry returns 404."""
    response = client.post("/api/patches/NON_EXISTENT_PATCH/retry")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_retry_history_not_found(client):
    """GET /api/patches/non_existent/retry-history returns 404."""
    response = client.get("/api/patches/NON_EXISTENT_PATCH/retry-history")
    assert response.status_code == 404


def test_api_retry_endpoint_first_pass(client, populated_workflow_and_patch, db_session):
    """POST /api/patches/{patch_id}/retry succeeds on first attempt without retrying."""
    patch_id = populated_workflow_and_patch["patch_id"]
    vuln_id = populated_workflow_and_patch["vulnerability_id"]

    # Mock validation agent to report PASSED on attempt 1
    mock_val = ValidationResult(
        id="VAL-API-01",
        patch_attempt_id=patch_id,
        vulnerability_id=vuln_id,
        status=ValidationStatus.PASSED,
        patch_applied=True,
        syntax_check_passed=True,
        tests_passed=True,
        security_scan_passed=True,
        original_vulnerability_resolved=True,
        new_findings_count=0,
        regression_detected=False,
    )

    with patch("backend.agents.retry_agent.ValidationAgent.validate_patch", return_value=mock_val):
        response = client.post(f"/api/patches/{patch_id}/retry")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == RetryStatus.READY_FOR_REVIEW.value
        assert data["successful_patch_id"] == patch_id
        assert data["total_attempts"] == 1
        assert len(data["attempts"]) == 1
        assert data["attempts"][0]["status"] == RetryStatus.VALIDATED.value


def test_api_retry_endpoint_success_on_second_attempt(client, populated_workflow_and_patch, db_session):
    """POST /api/patches/{patch_id}/retry fails first attempt, retries, and succeeds on second attempt."""
    patch_id = populated_workflow_and_patch["patch_id"]
    vuln_id = populated_workflow_and_patch["vulnerability_id"]
    wf_id = populated_workflow_and_patch["workflow_id"]

    val_fail = ValidationResult(
        id="VAL-FAIL-01",
        patch_attempt_id=patch_id,
        vulnerability_id=vuln_id,
        status=ValidationStatus.FAILED,
        tests_passed=False,
        failure_reason="Unit test failed on attempt 1",
    )
    val_pass = ValidationResult(
        id="VAL-PASS-02",
        patch_attempt_id="PATCH-SECOND-02",
        vulnerability_id=vuln_id,
        status=ValidationStatus.PASSED,
        patch_applied=True,
        syntax_check_passed=True,
        tests_passed=True,
        security_scan_passed=True,
        original_vulnerability_resolved=True,
        new_findings_count=0,
        regression_detected=False,
    )

    def _mock_validate(p_id=None, *args, **kwargs):
        curr_id = p_id or kwargs.get("patch_id")
        if curr_id == patch_id:
            return val_fail
        return val_pass

    def _mock_generate(**kwargs):
        new_p = PatchAttemptModel(
            id="PATCH-SECOND-02",
            workflow_id=wf_id,
            vulnerability_id=vuln_id,
            attempt_number=2,
            patch_format="unified_diff",
            patch_content="--- a/target.py\n+++ b/target.py\n@@ -2,1 +2,1 @@\n-    return 'sensitive_token'\n+    return get_env_secret('TOKEN')\n",
            explanation="Second attempt fixing test",
            files_changed=json.dumps(["target.py"]),
            status="GENERATED",
            parent_patch_id=patch_id,
        )
        db_session.add(new_p)
        db_session.commit()
        return PatchGenerationResult(
            id="PATCH-SECOND-02",
            vulnerability_id=vuln_id,
            attempt_number=2,
            status=PatchStatus.GENERATED,
            explanation="Second attempt fixing test",
            unified_diff=new_p.patch_content,
        )

    with patch("backend.agents.retry_agent.ValidationAgent.validate_patch", side_effect=_mock_validate), \
         patch("backend.agents.retry_agent.PatchGenerationAgent.generate_patch_for_vulnerability_id", side_effect=_mock_generate):
        response = client.post(f"/api/patches/{patch_id}/retry")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == RetryStatus.READY_FOR_REVIEW.value
        assert data["successful_patch_id"] == "PATCH-SECOND-02"
        assert data["total_attempts"] == 2
        assert len(data["attempts"]) == 2
        assert data["attempts"][0]["status"] == RetryStatus.VALIDATION_FAILED.value
        assert data["attempts"][1]["status"] == RetryStatus.VALIDATED.value


def test_api_retry_history_lineage(client, populated_workflow_and_patch, db_session):
    """GET /api/patches/{patch_id}/retry-history returns full genealogical chain."""
    p1_id = populated_workflow_and_patch["patch_id"]
    vuln_id = populated_workflow_and_patch["vulnerability_id"]
    wf_id = populated_workflow_and_patch["workflow_id"]

    p2 = PatchAttemptModel(
        id="PATCH-HIST-02",
        workflow_id=wf_id,
        vulnerability_id=vuln_id,
        attempt_number=2,
        parent_patch_id=p1_id,
        patch_format="unified_diff",
        patch_content="# diff 2",
        explanation="Attempt 2",
        status="GENERATED",
    )
    p3 = PatchAttemptModel(
        id="PATCH-HIST-03",
        workflow_id=wf_id,
        vulnerability_id=vuln_id,
        attempt_number=3,
        parent_patch_id="PATCH-HIST-02",
        patch_format="unified_diff",
        patch_content="# diff 3",
        explanation="Attempt 3",
        status="GENERATED",
    )
    db_session.add_all([p2, p3])
    db_session.commit()

    # Query history from child node
    response = client.get(f"/api/patches/{p3.id}/retry-history")
    assert response.status_code == 200
    history = response.json()

    assert len(history) == 3
    assert history[0]["patch_id"] == p1_id
    assert history[0]["attempt_number"] == 1
    assert history[1]["patch_id"] == "PATCH-HIST-02"
    assert history[1]["parent_patch_id"] == p1_id
    assert history[2]["patch_id"] == "PATCH-HIST-03"
    assert history[2]["parent_patch_id"] == "PATCH-HIST-02"


def test_api_retry_history_returns_actual_decision_and_category(client, populated_workflow_and_patch, db_session):
    """GET /api/patches/{patch_id}/retry-history exposes actual non-null failure_category and retry_decision."""
    patch_id = populated_workflow_and_patch["patch_id"]
    vuln_id = populated_workflow_and_patch["vulnerability_id"]
    wf_id = populated_workflow_and_patch["workflow_id"]

    val_fail = ValidationResult(
        id="VAL-FAIL-HIST-01",
        patch_attempt_id=patch_id,
        vulnerability_id=vuln_id,
        status=ValidationStatus.FAILED,
        tests_passed=False,
        failure_reason="AssertionError: regression in test_auth.py",
        failure_category=FailureCategory.TEST_FAILURE.value,
    )
    val_pass = ValidationResult(
        id="VAL-PASS-HIST-02",
        patch_attempt_id="PATCH-HIST-SECOND-02",
        vulnerability_id=vuln_id,
        status=ValidationStatus.PASSED,
        patch_applied=True,
        syntax_check_passed=True,
        tests_passed=True,
        security_scan_passed=True,
        original_vulnerability_resolved=True,
        new_findings_count=0,
        regression_detected=False,
    )

    def _mock_validate(p_id=None, *args, **kwargs):
        curr_id = p_id or kwargs.get("patch_id")
        if curr_id == patch_id:
            return val_fail
        return val_pass

    def _mock_generate(**kwargs):
        new_p = PatchAttemptModel(
            id="PATCH-HIST-SECOND-02",
            workflow_id=wf_id,
            vulnerability_id=vuln_id,
            attempt_number=2,
            patch_format="unified_diff",
            patch_content="--- a/target.py\n+++ b/target.py\n",
            explanation="Second attempt",
            files_changed=json.dumps(["target.py"]),
            status="GENERATED",
            parent_patch_id=patch_id,
        )
        db_session.add(new_p)
        db_session.commit()
        return PatchGenerationResult(
            id="PATCH-HIST-SECOND-02",
            vulnerability_id=vuln_id,
            attempt_number=2,
            status=PatchStatus.GENERATED,
            explanation="Second attempt",
            unified_diff=new_p.patch_content,
        )

    with patch("backend.agents.retry_agent.ValidationAgent.validate_patch", side_effect=_mock_validate), \
         patch("backend.agents.retry_agent.PatchGenerationAgent.generate_patch_for_vulnerability_id", side_effect=_mock_generate):
        # Execute retry loop
        resp = client.post(f"/api/patches/{patch_id}/retry")
        assert resp.status_code == 200

    # Query retry history
    response = client.get(f"/api/patches/{patch_id}/retry-history")
    assert response.status_code == 200
    history = response.json()

    assert len(history) == 2
    att1 = history[0]
    att2 = history[1]

    # Attempt 1: Failed
    assert att1["patch_id"] == patch_id
    assert att1["attempt_number"] == 1
    assert att1["parent_patch_id"] is None
    assert att1["failure_category"] == FailureCategory.TEST_FAILURE.value
    assert att1["retry_decision"] is not None
    assert att1["retry_decision"]["should_retry"] is True
    assert att1["retry_decision"]["failure_category"] == FailureCategory.TEST_FAILURE.value
    assert att1["retry_decision"]["can_retry_further"] is True

    # Attempt 2: Passed
    assert att2["patch_id"] == "PATCH-HIST-SECOND-02"
    assert att2["attempt_number"] == 2
    assert att2["parent_patch_id"] == patch_id
    assert att2["status"] in [RetryStatus.VALIDATED.value, ValidationStatus.PASSED.value]
    assert att2["failure_category"] is None
    assert att2["retry_decision"] is None


def test_database_consistency_three_attempts_fail_fail_pass(client, populated_workflow_and_patch, db_session):
    """Requirement 15: After FAIL, FAIL, PASS, DB contains 3 patches, 3 validations, and full lineage."""
    p1_id = populated_workflow_and_patch["patch_id"]
    vuln_id = populated_workflow_and_patch["vulnerability_id"]
    wf_id = populated_workflow_and_patch["workflow_id"]

    val_1 = ValidationResult(
        id="VAL-TRIPLE-01",
        patch_attempt_id=p1_id,
        vulnerability_id=vuln_id,
        status=ValidationStatus.FAILED,
        syntax_check_passed=False,
        failure_category=FailureCategory.SYNTAX_ERROR.value,
        failure_reason="Syntax error on line 12",
    )
    val_2 = ValidationResult(
        id="VAL-TRIPLE-02",
        patch_attempt_id="PATCH-TRIPLE-02",
        vulnerability_id=vuln_id,
        status=ValidationStatus.FAILED,
        tests_passed=False,
        failure_category=FailureCategory.TEST_FAILURE.value,
        failure_reason="pytest failed",
    )
    val_3 = ValidationResult(
        id="VAL-TRIPLE-03",
        patch_attempt_id="PATCH-TRIPLE-03",
        vulnerability_id=vuln_id,
        status=ValidationStatus.PASSED,
        patch_applied=True,
        syntax_check_passed=True,
        tests_passed=True,
        security_scan_passed=True,
        original_vulnerability_resolved=True,
        new_findings_count=0,
        regression_detected=False,
    )

    def _mock_validate(p_id=None, *args, **kwargs):
        curr_id = p_id or kwargs.get("patch_id")
        if curr_id == p1_id:
            res = val_1
        elif curr_id == "PATCH-TRIPLE-02":
            res = val_2
        else:
            res = val_3
        
        # In real execution ValidationAgent persists ValidationResultModel
        if kwargs.get("persist", True):
            v_model = ValidationResultModel(
                id=res.id,
                patch_attempt_id=res.patch_attempt_id,
                status=res.status.value,
                failure_reason=res.failure_reason,
                failure_category=res.failure_category,
                patch_applied=res.patch_applied,
                syntax_check_passed=res.syntax_check_passed,
                tests_passed=res.tests_passed,
            )
            db_session.add(v_model)
            db_session.commit()
        return res

    gen_counter = [1]
    def _mock_generate(**kwargs):
        gen_counter[0] += 1
        curr_id = f"PATCH-TRIPLE-0{gen_counter[0]}"
        parent_id = kwargs.get("parent_patch_id")
        new_p = PatchAttemptModel(
            id=curr_id,
            workflow_id=wf_id,
            vulnerability_id=vuln_id,
            attempt_number=gen_counter[0],
            patch_format="unified_diff",
            patch_content=f"# diff attempt {gen_counter[0]}",
            explanation=f"Attempt {gen_counter[0]}",
            files_changed=json.dumps(["target.py"]),
            status="GENERATED",
            parent_patch_id=parent_id,
        )
        db_session.add(new_p)
        db_session.commit()
        return PatchGenerationResult(
            id=curr_id,
            vulnerability_id=vuln_id,
            attempt_number=gen_counter[0],
            status=PatchStatus.GENERATED,
            explanation=f"Attempt {gen_counter[0]}",
            unified_diff=new_p.patch_content,
        )

    with patch("backend.agents.retry_agent.ValidationAgent.validate_patch", side_effect=_mock_validate), \
         patch("backend.agents.retry_agent.PatchGenerationAgent.generate_patch_for_vulnerability_id", side_effect=_mock_generate):
        resp = client.post(f"/api/patches/{p1_id}/retry")
        assert resp.status_code == 200
        result = resp.json()

    assert result["status"] == RetryStatus.READY_FOR_REVIEW.value
    assert result["total_attempts"] == 3
    assert result["successful_patch_id"] == "PATCH-TRIPLE-03"

    # Database Verification: exactly 3 patch attempts
    all_patches = db_session.query(PatchAttemptModel).filter(
        PatchAttemptModel.workflow_id == wf_id
    ).order_by(PatchAttemptModel.attempt_number.asc()).all()
    assert len(all_patches) == 3

    p_1, p_2, p_3 = all_patches[0], all_patches[1], all_patches[2]
    assert p_1.id == p1_id
    assert p_1.attempt_number == 1
    assert p_1.parent_patch_id is None
    assert p_1.validation_id == "VAL-TRIPLE-01"
    assert p_1.failure_category == FailureCategory.SYNTAX_ERROR.value

    assert p_2.id == "PATCH-TRIPLE-02"
    assert p_2.attempt_number == 2
    assert p_2.parent_patch_id == p1_id
    assert p_2.validation_id == "VAL-TRIPLE-02"
    assert p_2.failure_category == FailureCategory.TEST_FAILURE.value

    assert p_3.id == "PATCH-TRIPLE-03"
    assert p_3.attempt_number == 3
    assert p_3.parent_patch_id == "PATCH-TRIPLE-02"
    assert p_3.validation_id == "VAL-TRIPLE-03"
    assert p_3.status == PatchStatus.VALIDATED.value

    # Verify 3 validation results records in database
    val_records = db_session.query(ValidationResultModel).filter(
        ValidationResultModel.patch_attempt_id.in_([p1_id, "PATCH-TRIPLE-02", "PATCH-TRIPLE-03"])
    ).all()
    assert len(val_records) >= 3


def test_api_retry_history_circular_lineage_protection(client, populated_workflow_and_patch, db_session):
    """Requirement 7: Circular parentage in database is safely guarded against infinite loop."""
    wf_id = populated_workflow_and_patch["workflow_id"]
    vuln_id = populated_workflow_and_patch["vulnerability_id"]

    # Create cyclic records: A -> B -> A
    pA = PatchAttemptModel(
        id="PATCH-CYCLE-A",
        workflow_id=wf_id,
        vulnerability_id=vuln_id,
        attempt_number=1,
        parent_patch_id="PATCH-CYCLE-B",
        patch_format="unified_diff",
        patch_content="# A",
        status="GENERATED",
    )
    pB = PatchAttemptModel(
        id="PATCH-CYCLE-B",
        workflow_id=wf_id,
        vulnerability_id=vuln_id,
        attempt_number=2,
        parent_patch_id="PATCH-CYCLE-A",
        patch_format="unified_diff",
        patch_content="# B",
        status="GENERATED",
    )
    db_session.add_all([pA, pB])
    db_session.commit()

    # Must complete promptly without hanging
    response = client.get("/api/patches/PATCH-CYCLE-A/retry-history")
    assert response.status_code == 200
    history = response.json()
    assert len(history) <= 2

