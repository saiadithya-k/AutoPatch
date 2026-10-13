"""Real-tool workflow, retry and persistent review without an external model."""
import pytest
from backend.database.models import PatchAttemptModel, ValidationResultModel, WorkflowModel
from scripts.demo_workflow import create_demo_repository, run_demo, source_hashes

pytestmark = pytest.mark.scanners


def test_real_workflow_retries_then_reviews_with_source_unchanged(tmp_path, db_session, client):
    repository = tmp_path / "literal-parser"
    create_demo_repository(repository)
    before = source_hashes(repository)
    workflow = run_demo(db_session, repository)
    assert workflow.status == "READY_FOR_REVIEW", workflow.error_message
    assert workflow.outcome == "REVIEWABLE"
    assert workflow.processed_findings == workflow.total_findings >= 1
    assert workflow.reviewable_count == workflow.total_findings
    patches = db_session.query(PatchAttemptModel).filter_by(workflow_id=workflow.id).all()
    assert len(patches) == workflow.total_findings * 2
    initial = [p for p in patches if p.attempt_number == 1]
    candidates = [p for p in patches if p.attempt_number == 2]
    assert all(p.status == "FAILED_VALIDATION" for p in initial)
    assert all(p.status == "READY_FOR_REVIEW" and p.parent_patch_id in {old.id for old in initial} for p in candidates)
    for patch in candidates:
        validation = db_session.get(ValidationResultModel, patch.validation_id)
        assert validation.status == "PASSED"
        assert validation.security_scan_passed and validation.tests_passed
        assert validation.original_vulnerability_resolved
        assert validation.new_findings_count == 0
        response = client.post(f"/api/patches/{patch.id}/approve", json={"reviewer_label": "Demo reviewer", "comment": "Verified real test and scan evidence"})
        assert response.status_code == 200, response.text
        assert client.post(f"/api/patches/{patch.id}/approve", json={"reviewer_label": "Demo reviewer", "comment": "Verified real test and scan evidence"}).status_code == 200
        assert client.post(f"/api/patches/{patch.id}/reject", json={"reviewer_label": "Demo reviewer", "comment": "Conflicting decision"}).status_code == 409
    db_session.expire_all()
    assert db_session.get(WorkflowModel, workflow.id).status == "APPROVED"
    report = client.get(f"/api/reports/{workflow.id}").json()
    assert len(report["reviews"]) == workflow.total_findings
    assert len(report["validations"]) == len(patches)
    assert report["unresolved_findings"] == []
    event_types = {event["event_type"] for event in report["audit_events"]}
    assert {"RETRY_STARTED", "PATCH_VALIDATED", "PATCH_APPROVED"} <= event_types
    assert source_hashes(repository) == before
