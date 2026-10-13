"""Reviewed proposals and their evidence cannot be replaced by validation/retry."""
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.agents.validation_agent import PatchLifecycleConflict, ValidationAgent
from backend.agents.retry_agent import RetryAgent
from backend.api.routes.validation import validate_patch_endpoint
from backend.api.routes.retry import run_patch_retry_endpoint
from backend.database.database import Base
from backend.database.models import PatchAttemptModel
from backend.models.validation import ValidationStatus
from backend.models.vulnerability import VulnerabilityFinding


@pytest.fixture
def reviewed_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(PatchAttemptModel(id="p", vulnerability_id="v", workflow_id="w", attempt_number=1,
            patch_content="original evidence", status="APPROVED", validation_id="original-validation"))
        session.commit()
        yield session


@pytest.mark.parametrize("state", ["APPROVED", "REJECTED"])
@pytest.mark.parametrize("endpoint", [validate_patch_endpoint, run_patch_retry_endpoint])
def test_reviewed_candidate_api_returns_conflict(reviewed_session, state, endpoint):
    record = reviewed_session.get(PatchAttemptModel, "p")
    record.status = state
    reviewed_session.commit()
    with pytest.raises(HTTPException) as error:
        endpoint("p", db=reviewed_session)
    assert error.value.status_code == 409
    assert record.validation_id == "original-validation"
    assert record.status == state


def test_validation_status_update_cannot_overwrite_decision(reviewed_session):
    with pytest.raises(PatchLifecycleConflict):
        ValidationAgent()._update_patch_status("p", "VALIDATING", reviewed_session)
    record = reviewed_session.get(PatchAttemptModel, "p")
    assert record.status == "APPROVED"
    assert record.validation_id == "original-validation"


def test_finalization_cannot_replace_reviewed_evidence(reviewed_session, tmp_path):
    agent = ValidationAgent()
    finding = VulnerabilityFinding(id="v", tool="bandit", type="unsafe", file_path="app.py", description="unsafe")
    with pytest.raises(PatchLifecycleConflict):
        agent._finalize_and_verify_immutability(val_id="new-validation", patch_id="p", vulnerability=finding,
            workflow_id="w", status=ValidationStatus.PASSED, patch_applied=True, syntax_passed=True,
            tests_passed=True, sec_scan_passed=True, orig_resolved=True, regression=False, failure_reason=None,
            validation_logs="", duration=0.1, started_at=datetime.utcnow(), repository_path=tmp_path,
            initial_hashes={}, db_session=reviewed_session)
    record = reviewed_session.get(PatchAttemptModel, "p")
    assert record.status == "APPROVED"
    assert record.validation_id == "original-validation"


def test_retry_agent_rejects_decided_candidate(reviewed_session):
    validator = MagicMock()
    with pytest.raises(PatchLifecycleConflict):
        RetryAgent(validation_agent=validator).run_retry_loop("p", db_session=reviewed_session)
    validator.validate_patch.assert_not_called()
