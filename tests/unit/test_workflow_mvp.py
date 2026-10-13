"""Workflow aggregation, persisted reviews, restart recovery, and migration."""
from types import SimpleNamespace
from unittest.mock import MagicMock
from contextlib import contextmanager
import threading
from datetime import timedelta
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, inspect, text
from backend.database.database import apply_mvp_migrations
from backend.database.models import WorkflowModel, VulnerabilityModel, PatchAttemptModel, ValidationResultModel, ReviewDecisionModel
from backend.models.workflow import ReviewRequest
from backend.services.review import record_review
from backend.services.reports import workflow_report
from backend.services.workflows import WorkflowRunner, WorkflowJobs


def seed(db):
    wf = WorkflowModel(id="wf-mvp", repository_path="demo", max_retries=0, status="CREATED")
    db.add(wf)
    db.commit()
    return wf


def test_clean_scan_is_complete_not_failed(db_session):
    wf = seed(db_session)
    scanner = MagicMock()
    scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True})
    WorkflowRunner(scanner=scanner, risk=MagicMock(), generator=MagicMock(), retry=MagicMock()).run(db_session, wf.id)
    assert wf.status == "COMPLETED"
    assert wf.outcome == "NO_FINDINGS"
    assert scanner.scan.call_args.kwargs["manage_workflow"] is False


def test_degraded_scan_never_reports_no_findings(db_session):
    wf = seed(db_session)
    scanner = MagicMock()
    scanner.scan.return_value = ([], {"scan_status": "DEGRADED", "errors": ["Semgrep unavailable"]})
    risk = MagicMock()
    WorkflowRunner(scanner=scanner, risk=risk, generator=MagicMock(), retry=MagicMock()).run(db_session, wf.id)
    assert wf.outcome == "SCAN_INCONCLUSIVE"
    assert wf.status == "FAILED"
    risk.assess_workflow.assert_not_called()


def test_workflow_continues_after_finding_failure_and_validates_once(db_session):
    wf = seed(db_session)
    scanner, risk, generator, retry = (MagicMock() for _ in range(4))
    scanner.scan.return_value = ([object(), object()], {"scan_status": "COMPLETED", "coverage_complete": True})
    def finding(name):
        return SimpleNamespace(vulnerability=SimpleNamespace(id=name), risk_assessment=SimpleNamespace(priority=SimpleNamespace(value="HIGH")))
    risk.assess_workflow.return_value = [finding("v1"), finding("v2")]
    generator.generate_patch_for_vulnerability_id.side_effect = [ValueError("model failure"), SimpleNamespace(id="p2", status=SimpleNamespace(value="GENERATED"))]
    retry.run_retry_loop.return_value = SimpleNamespace(successful_patch_id="p2")
    WorkflowRunner(scanner=scanner, risk=risk, generator=generator, retry=retry).run(db_session, wf.id)
    assert wf.status == "READY_FOR_REVIEW"
    assert wf.outcome == "PARTIAL_SUCCESS"
    assert (wf.processed_findings, wf.failed_count, wf.reviewable_count) == (2, 1, 1)
    retry.run_retry_loop.assert_called_once_with("p2", max_retries=0, db_session=db_session)


def proposal(db, valid=True):
    wf = seed(db)
    vuln = VulnerabilityModel(id="v1", workflow_id=wf.id, tool="bandit", type="issue", severity="HIGH", file_path="app.py", description="issue")
    patch = PatchAttemptModel(id="p1", workflow_id=wf.id, vulnerability_id="v1", patch_content="diff", status="READY_FOR_REVIEW")
    db.add_all([vuln, patch])
    if valid:
        db.add(ValidationResultModel(id="val1", patch_attempt_id="p1", status="PASSED", patch_applied=True, syntax_check_passed=True, tests_passed=True, security_scan_passed=True, original_vulnerability_resolved=True, new_findings_count=0, scanner_metadata='{"coverage_complete": true}'))
    db.commit()
    return wf, patch


def test_approval_requires_evidence(db_session):
    proposal(db_session, valid=False)
    with pytest.raises(HTTPException) as error:
        record_review(db_session, "p1", "APPROVED", ReviewRequest(reviewer_label="Developer"))
    assert error.value.status_code == 409
    assert db_session.query(ReviewDecisionModel).count() == 0


def test_review_is_persistent_idempotent_and_conflicting_decision_rejected(db_session):
    wf, patch = proposal(db_session)
    request = ReviewRequest(reviewer_label="Developer", comment="Reviewed")
    review = record_review(db_session, "p1", "APPROVED", request)
    assert record_review(db_session, "p1", "APPROVED", request).id == review.id
    assert patch.status == "APPROVED"
    with pytest.raises(HTTPException) as error:
        record_review(db_session, "p1", "REJECTED", request)
    assert error.value.status_code == 409
    report = workflow_report(db_session, wf)
    assert report["reviews"][0]["validation_id"] == "val1"
    assert report["unresolved_findings"] == []
    assert db_session.get(VulnerabilityModel, "v1").status != "REMEDIATED"


def test_additive_migration_is_idempotent(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE workflows (id VARCHAR PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE validation_results (id VARCHAR PRIMARY KEY)"))
        conn.execute(text("INSERT INTO workflows (id) VALUES ('keep')"))
    apply_mvp_migrations(engine)
    apply_mvp_migrations(engine)
    assert "scanner_metadata" in {c["name"] for c in inspect(engine).get_columns("validation_results")}
    with engine.connect() as conn:
        assert conn.execute(text("SELECT id, processed_findings FROM workflows")).one() == ("keep", 0)


def test_restart_marks_active_workflow_interrupted(db_session):
    wf = seed(db_session)
    wf.status = "VALIDATING"
    db_session.commit()
    @contextmanager
    def session():
        yield db_session
    jobs = WorkflowJobs(session_factory=session)
    jobs.recover()
    assert wf.status == "FAILED"
    assert wf.outcome == "INTERRUPTED"
    assert wf.completed_at is not None
    jobs.shutdown()
    jobs.start()
    jobs.shutdown()


def test_background_queue_is_bounded_and_deduplicates():
    started, release = threading.Event(), threading.Event()
    @contextmanager
    def session():
        yield None
    class Runner:
        def run(self, db, workflow_id):
            started.set()
            release.wait(5)
    jobs = WorkflowJobs(session_factory=session, runner_factory=Runner, workers=1, capacity=1)
    try:
        assert jobs.submit("one") is True
        assert started.wait(2)
        assert jobs.submit("one") is False
        with pytest.raises(RuntimeError, match="capacity"):
            jobs.submit("two")
    finally:
        release.set()
        jobs.shutdown()
    assert not jobs.active


def test_approval_rejects_stale_proposal_and_incomplete_coverage(db_session):
    _, patch = proposal(db_session)
    evidence = db_session.get(ValidationResultModel, "val1")
    evidence.scanner_metadata = '{"coverage_complete": false}'
    db_session.commit()
    with pytest.raises(HTTPException) as error:
        record_review(db_session, patch.id, "APPROVED", ReviewRequest(reviewer_label="Developer"))
    assert error.value.status_code == 409
    evidence.scanner_metadata = '{"coverage_complete": true}'
    db_session.add(PatchAttemptModel(id="p-new", workflow_id=patch.workflow_id, vulnerability_id=patch.vulnerability_id, attempt_number=2, patch_content="new diff", status="GENERATED"))
    db_session.commit()
    with pytest.raises(HTTPException) as error:
        record_review(db_session, patch.id, "APPROVED", ReviewRequest(reviewer_label="Developer"))
    assert "newer candidate" in error.value.detail


def test_review_waits_for_running_orchestration(db_session):
    wf, patch = proposal(db_session)
    wf.request_json = '{}'
    wf.status = "VALIDATING"
    db_session.commit()
    with pytest.raises(HTTPException) as error:
        record_review(db_session, patch.id, "APPROVED", ReviewRequest(reviewer_label="Developer"))
    assert error.value.status_code == 409
    assert "workflow finishes" in error.value.detail


def test_latest_same_attempt_supersedes_old_ready_candidate(db_session):
    wf, old = proposal(db_session)
    from backend.database.models import utc_now
    wf.completed_at = utc_now()
    wf.total_findings = wf.processed_findings = 1
    newer = PatchAttemptModel(id="p-new", workflow_id=wf.id, vulnerability_id=old.vulnerability_id, attempt_number=old.attempt_number, patch_content="new", status="READY_FOR_REVIEW", created_at=old.created_at + timedelta(seconds=1))
    db_session.add(newer)
    db_session.commit()
    with pytest.raises(HTTPException) as error:
        record_review(db_session, old.id, "APPROVED", ReviewRequest(reviewer_label="Developer"))
    assert error.value.status_code == 409
    record_review(db_session, newer.id, "REJECTED", ReviewRequest(reviewer_label="Developer", comment="Incorrect"))
    assert wf.reviewable_count == 0
    assert wf.status == "REJECTED"
    assert workflow_report(db_session, wf)["unresolved_findings"] == [old.vulnerability_id]


def test_malformed_review_evidence_fails_closed_and_report_remains_readable(db_session):
    wf, patch = proposal(db_session)
    evidence = db_session.get(ValidationResultModel, "val1")
    evidence.scanner_metadata = '[]'
    evidence.new_findings = 'invalid json'
    patch.files_changed = '[{}]'
    wf.errors_json = '[{}]'
    db_session.commit()
    with pytest.raises(HTTPException) as error:
        record_review(db_session, patch.id, "APPROVED", ReviewRequest(reviewer_label="Developer"))
    assert error.value.status_code == 409
    report = workflow_report(db_session, wf)
    assert report["validations"][0]["scanner_metadata"] == {}
    assert report["validations"][0]["new_findings"] == []
    assert report["patches"][0]["files_changed"] == []
    assert {error["field"] for error in report["evidence_errors"]} == {"scanner_metadata", "new_findings", "files_changed", "errors_json"}
