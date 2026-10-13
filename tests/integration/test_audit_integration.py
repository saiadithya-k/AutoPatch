"""Integration tests for Phase 11: Database + Audit Lifecycle and API Endpoints.

Verifies:
1. ScanningAgent creates SCAN_STARTED and SCAN_COMPLETED / SCAN_DEGRADED events.
2. RiskAssessmentAgent creates RISK_ASSESSMENT_STARTED and RISK_ASSESSMENT_COMPLETED events.
3. PatchGenerationAgent creates PATCH_GENERATION_STARTED and PATCH_GENERATED events.
4. ValidationAgent creates PATCH_VALIDATION_STARTED, PATCH_APPLIED, and PATCH_VALIDATED/PATCH_VALIDATION_FAILED events.
5. Validation success triggers READY_FOR_REVIEW event.
6. RetryAgent creates RETRY_DECISION and RETRY_STARTED events.
7. Retry exhaustion creates RETRY_EXHAUSTED event.
8. No-progress creates NO_PROGRESS event.
9. Chronological ordering in GET /api/workflows/{workflow_id}/audit timeline.
10. Filtering in GET /api/audit/events (by workflow, vuln, patch, event_type).
11. Pagination in GET /api/audit/events.
12. Audit records persist reliably across database sessions.
"""

from pathlib import Path
from datetime import timedelta
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.agents.retry_agent import RetryAgent
from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.agents.scanning_agent import ScanningAgent
from backend.agents.validation_agent import ValidationAgent
from backend.database.models import (
    AuditEventModel,
    PatchAttemptModel,
    RiskAssessmentModel,
    ValidationResultModel,
    VulnerabilityModel,
    WorkflowModel,
)
from backend.models.audit import AuditEventStatus, AuditEventType
from backend.models.patch import PatchGenerationResult, PatchStatus
from backend.models.repository_context import RepositoryContext
from backend.models.retry import FailureCategory, RetryDecision, RetryStatus
from backend.models.risk_assessment import PriorityLevel, RiskAssessment
from backend.models.validation import ValidationResult, ValidationStatus
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
)
from backend.services.audit import AuditService
from backend.services.llm.mock_provider import MockLLMProvider
from backend.services.llm.service import LLMService
from backend.tools.bandit_runner import BanditResult, BanditRunner
from backend.tools.semgrep_runner import SemgrepResult, SemgrepRunner


@pytest.fixture
def test_workflow_setup(db_session: Session, tmp_path: Path):
    """Setup a sample repository and workflow records for audit integration tests."""
    repo_dir = tmp_path / "audit_test_repo"
    repo_dir.mkdir()
    app_file = repo_dir / "app.py"
    app_file.write_text(
        "import os\n\ndef run_cmd(cmd):\n    return os.system(cmd)\n",
        encoding="utf-8"
    )

    wf_id = "wf-audit-e2e-01"
    wf = WorkflowModel(
        id=wf_id,
        repository_path=str(repo_dir),
        status="IN_PROGRESS",
    )
    db_session.add(wf)

    vuln = VulnerabilityModel(
        id="VULN-AUDIT-01",
        workflow_id=wf_id,
        tool="bandit",
        rule_id="B605",
        type="command_injection",
        cwe="CWE-78",
        severity="HIGH",
        confidence="HIGH",
        file_path="app.py",
        line_start=4,
        line_end=4,
        code_snippet="return os.system(cmd)",
        description="Possible command injection in os.system",
        status="DETECTED",
    )
    db_session.add(vuln)
    db_session.commit()

    return {
        "workflow_id": wf_id,
        "vulnerability_id": vuln.id,
        "repo_dir": repo_dir,
        "vuln_finding": VulnerabilityFinding(
            id=vuln.id,
            workflow_id=wf_id,
            tool=vuln.tool,
            rule_id=vuln.rule_id,
            type=vuln.type,
            cwe=vuln.cwe,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path=vuln.file_path,
            line_start=vuln.line_start,
            line_end=vuln.line_end,
            code_snippet=vuln.code_snippet,
            description=vuln.description,
            status=VulnerabilityStatus.DETECTED,
        ),
    }


class TestAuditIntegrationLifecycle:
    """Test suite verifying agents emit appropriate audit events across the lifecycle."""

    def test_scan_creates_audit_events(self, db_session: Session, test_workflow_setup):
        """1. Verify ScanningAgent records SCAN_STARTED and SCAN_COMPLETED."""
        repo_dir = test_workflow_setup["repo_dir"]
        wf_id = test_workflow_setup["workflow_id"]

        mock_bandit = MagicMock(spec=BanditRunner)
        mock_bandit.run.return_value = BanditResult(
            findings=[{"test_id": "B605", "filename": "app.py", "line_number": 4, "code": "os.system(cmd)", "issue_severity": "HIGH"}],
            exit_code=0,
            success=True,
            stdout="{}",
        )
        mock_semgrep = MagicMock(spec=SemgrepRunner)
        mock_semgrep.run.return_value = SemgrepResult(
            findings=[],
            exit_code=0,
            success=True,
            stdout="{}",
        )

        agent = ScanningAgent(
            bandit_runner=mock_bandit,
            semgrep_runner=mock_semgrep,
        )

        findings, meta = agent.scan(
            repository_path=repo_dir,
            workflow_id=wf_id,
            persist=True,
            db_session=db_session,
        )

        events = db_session.query(AuditEventModel).filter(
            AuditEventModel.workflow_id == wf_id
        ).all()
        types = [e.event_type for e in events]

        assert AuditEventType.SCAN_STARTED.value in types
        assert (
            AuditEventType.SCAN_COMPLETED.value in types
            or AuditEventType.SCAN_DEGRADED.value in types
        )

    def test_risk_assessment_creates_audit_events(self, db_session: Session, test_workflow_setup):
        """2. Verify RiskAssessmentAgent records RISK_ASSESSMENT_STARTED and RISK_ASSESSMENT_COMPLETED."""
        wf_id = test_workflow_setup["workflow_id"]
        finding = test_workflow_setup["vuln_finding"]

        agent = RiskAssessmentAgent()
        results = agent.assess(
            findings=[finding],
            workflow_id=wf_id,
            persist=True,
            db_session=db_session,
        )

        events = db_session.query(AuditEventModel).filter(
            AuditEventModel.workflow_id == wf_id
        ).all()
        types = [e.event_type for e in events]

        assert AuditEventType.RISK_ASSESSMENT_STARTED.value in types
        assert AuditEventType.RISK_ASSESSMENT_COMPLETED.value in types

        comp_event = next(e for e in events if e.event_type == AuditEventType.RISK_ASSESSMENT_COMPLETED.value)
        meta = comp_event.get_metadata()
        assert meta["finding_count"] == 1
        assert meta["prioritized_count"] == 1

    def test_patch_generation_creates_audit_events(self, db_session: Session, test_workflow_setup):
        """3. Verify PatchGenerationAgent records PATCH_GENERATION_STARTED and PATCH_GENERATED."""
        wf_id = test_workflow_setup["workflow_id"]
        finding = test_workflow_setup["vuln_finding"]
        finding.status = VulnerabilityStatus.PRIORITIZED

        mock_provider = MockLLMProvider(
            canned_content='''{
                "explanation": "Replace os.system with safe subprocess list",
                "changes": [
                    {
                        "file_path": "app.py",
                        "start_line": 4,
                        "end_line": 4,
                        "original_code": "    return os.system(cmd)",
                        "replacement_code": "    return subprocess.run([cmd], shell=False).returncode"
                    }
                ],
                "unified_diff": "--- a/app.py\\n+++ b/app.py\\n@@ -4,1 +4,1 @@\\n-return os.system(cmd)\\n+return subprocess.run([cmd], shell=False).returncode\\n",
                "assumptions": ["cmd is clean"],
                "tests_to_run": []
            }'''
        )
        llm_service = LLMService(provider=mock_provider)
        agent = PatchGenerationAgent(llm_service=llm_service)

        risk_assessment = RiskAssessment(
            id="RISK-AUDIT-01",
            vulnerability_id=finding.id,
            workflow_id=wf_id,
            severity="HIGH",
            severity_score=8.0,
            context_score=1.0,
            exploitability=0.8,
            business_impact=0.8,
            risk_score=8.5,
            priority=PriorityLevel.CRITICAL,
            reasoning="Command injection",
        )

        context = RepositoryContext(
            vulnerability_id=finding.id,
            vulnerable_file="app.py",
            line_start=4,
            line_end=4,
            surrounding_code="def run_cmd(cmd):\n    return os.system(cmd)\n",
            context_window_start=1,
            context_window_end=4,
            repository_root=str(test_workflow_setup["repo_dir"]),
        )

        result = agent.generate_patch(
            vulnerability=finding,
            risk_assessment=risk_assessment,
            repository_context=context,
            attempt_number=1,
            persist=True,
            db_session=db_session,
        )

        events = db_session.query(AuditEventModel).filter(
            AuditEventModel.vulnerability_id == finding.id
        ).all()
        types = [e.event_type for e in events]

        assert AuditEventType.PATCH_GENERATION_STARTED.value in types
        assert AuditEventType.PATCH_GENERATED.value in types

    def test_validation_creates_audit_events_and_ready_for_review(self, db_session: Session, test_workflow_setup):
        """4 & 5. Verify ValidationAgent records PATCH_VALIDATION_STARTED, PATCH_APPLIED, PATCH_VALIDATED, and READY_FOR_REVIEW."""
        wf_id = test_workflow_setup["workflow_id"]
        finding = test_workflow_setup["vuln_finding"]
        repo_dir = test_workflow_setup["repo_dir"]

        patch_id = "PATCH-VAL-TEST-01"
        valid_diff = "--- a/app.py\n+++ b/app.py\n@@ -4,1 +4,1 @@\n-    return os.system(cmd)\n+    return 0\n"

        p_rec = PatchAttemptModel(
            id=patch_id,
            workflow_id=wf_id,
            vulnerability_id=finding.id,
            attempt_number=1,
            patch_content=valid_diff,
            status="GENERATED",
        )
        db_session.add(p_rec)
        db_session.commit()

        # Mock successful validation dependencies
        mock_test_runner = MagicMock()
        mock_test_runner.run_tests.return_value = MagicMock(
            success=True,
            exit_code=0,
            tests_run=5,
            tests_passed=5,
            tests_failed=0,
            tests_skipped=0,
            duration=0.5,
            error_message=None,
            stdout="5 passed",
            stderr="",
        )

        mock_scan_agent = MagicMock()
        mock_scan_agent.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True, "bandit": {"success": True}, "semgrep": {"success": True}, "errors": []})

        agent = ValidationAgent(
            test_runner=mock_test_runner,
            scanning_agent=mock_scan_agent,
        )
        # Mock syntax check to succeed
        agent._run_syntax_check = MagicMock(return_value=(True, "Syntax passed"))

        val_result = agent.execute_validation(
            patch_id=patch_id,
            vulnerability=finding,
            unified_diff=valid_diff,
            repository_path=repo_dir,
            workflow_id=wf_id,
            persist=True,
            db_session=db_session,
        )

        assert val_result.status == ValidationStatus.PASSED

        events = db_session.query(AuditEventModel).filter(
            AuditEventModel.patch_attempt_id == patch_id
        ).all()
        types = [e.event_type for e in events]

        assert AuditEventType.PATCH_VALIDATION_STARTED.value in types
        assert AuditEventType.PATCH_APPLIED.value in types
        assert AuditEventType.PATCH_VALIDATED.value in types
        assert AuditEventType.READY_FOR_REVIEW.value in types

    def test_retry_creates_decision_and_exhausted_events(self, db_session: Session, test_workflow_setup):
        """6 & 7. Verify RetryAgent records RETRY_DECISION and RETRY_EXHAUSTED."""
        wf_id = test_workflow_setup["workflow_id"]
        finding = test_workflow_setup["vuln_finding"]

        patch_id = "PATCH-RETRY-TEST-01"
        p_rec = PatchAttemptModel(
            id=patch_id,
            workflow_id=wf_id,
            vulnerability_id=finding.id,
            attempt_number=1,
            patch_content="--- a/app.py\n+++ b/app.py\n",
            status="GENERATED",
        )
        db_session.add(p_rec)
        db_session.commit()

        # Mock ValidationAgent that always fails
        mock_val_agent = MagicMock()
        mock_val_agent.validate_patch.return_value = ValidationResult(
            id="VAL-FAIL-01",
            patch_attempt_id=patch_id,
            vulnerability_id=finding.id,
            workflow_id=wf_id,
            status=ValidationStatus.FAILED,
            patch_applied=True,
            syntax_check_passed=True,
            tests_passed=False,
            failure_reason="Unit tests failed",
            failure_category=FailureCategory.TEST_FAILURE.value,
        )

        agent = RetryAgent(
            validation_agent=mock_val_agent,
            max_retries=1,
        )
        # Mock patch generation to return a new patch attempt model
        mock_gen_result = MagicMock(spec=PatchGenerationResult)
        mock_gen_result.id = "PATCH-RETRY-TEST-02"

        def _mock_gen(**kwargs):
            new_p = PatchAttemptModel(
                id="PATCH-RETRY-TEST-02",
                workflow_id=wf_id,
                vulnerability_id=finding.id,
                parent_patch_id=patch_id,
                attempt_number=2,
                patch_content="--- a/app.py\n+++ b/app.py\n# new code\n",
                status="GENERATED",
            )
            db_session.add(new_p)
            db_session.commit()
            return mock_gen_result

        agent.patch_generation_agent.generate_patch_for_vulnerability_id = MagicMock(side_effect=_mock_gen)

        res = agent.run_retry_loop(
            initial_patch_id=patch_id,
            max_retries=1,
            db_session=db_session,
        )

        assert res.status == RetryStatus.RETRY_EXHAUSTED.value

        events = db_session.query(AuditEventModel).filter(
            AuditEventModel.workflow_id == wf_id
        ).all()
        types = [e.event_type for e in events]

        assert AuditEventType.RETRY_DECISION.value in types
        assert AuditEventType.RETRY_STARTED.value in types
        assert AuditEventType.RETRY_EXHAUSTED.value in types

    def test_no_progress_creates_no_progress_event(self, db_session: Session, test_workflow_setup):
        """8. Verify identical generated patch triggers NO_PROGRESS audit event."""
        wf_id = test_workflow_setup["workflow_id"]
        finding = test_workflow_setup["vuln_finding"]

        patch_id_1 = "PATCH-PROG-01"
        p_rec_1 = PatchAttemptModel(
            id=patch_id_1,
            workflow_id=wf_id,
            vulnerability_id=finding.id,
            attempt_number=1,
            patch_content="identical diff content",
            status="GENERATED",
        )
        db_session.add(p_rec_1)
        db_session.commit()

        mock_val_agent = MagicMock()
        mock_val_agent.validate_patch.return_value = ValidationResult(
            id="VAL-FAIL-PROG",
            patch_attempt_id=patch_id_1,
            vulnerability_id=finding.id,
            workflow_id=wf_id,
            status=ValidationStatus.FAILED,
            patch_applied=True,
            syntax_check_passed=True,
            tests_passed=False,
            failure_reason="Failed tests",
            failure_category=FailureCategory.TEST_FAILURE.value,
        )

        agent = RetryAgent(validation_agent=mock_val_agent, max_retries=2)

        # The generator returns a patch with EXACT SAME content
        def _mock_identical_gen(**kwargs):
            new_p = PatchAttemptModel(
                id="PATCH-PROG-02",
                workflow_id=wf_id,
                vulnerability_id=finding.id,
                parent_patch_id=patch_id_1,
                attempt_number=2,
                patch_content="identical diff content",
                status="GENERATED",
            )
            db_session.add(new_p)
            db_session.commit()
            return MagicMock(id="PATCH-PROG-02")

        agent.patch_generation_agent.generate_patch_for_vulnerability_id = MagicMock(side_effect=_mock_identical_gen)

        res = agent.run_retry_loop(initial_patch_id=patch_id_1, db_session=db_session)

        assert res.status == RetryStatus.NO_PROGRESS.value

        events = db_session.query(AuditEventModel).filter(
            AuditEventModel.event_type == AuditEventType.NO_PROGRESS.value
        ).all()
        assert len(events) >= 1


class TestAuditAPIIntegration:
    """Test suite for /api/audit REST endpoints and timeline queries."""

    def test_workflow_timeline_is_chronological(self, client: TestClient, db_session: Session):
        """9. Verify GET /api/workflows/{workflow_id}/audit returns chronological events."""
        wf_id = "wf-timeline-check"
        wf = WorkflowModel(id=wf_id, repository_path="/test")
        db_session.add(wf)

        service = AuditService()
        e1 = service.record_event(
            event_type=AuditEventType.SCAN_STARTED,
            workflow_id=wf_id,
            session=db_session,
        )
        e2 = service.record_event(
            event_type=AuditEventType.SCAN_COMPLETED,
            workflow_id=wf_id,
            session=db_session,
        )
        e3 = service.record_event(
            event_type=AuditEventType.RISK_ASSESSMENT_STARTED,
            workflow_id=wf_id,
            session=db_session,
        )
        # Windows clocks can give successive events identical timestamps.
        e2.created_at = e1.created_at + timedelta(seconds=1)
        e3.created_at = e1.created_at + timedelta(seconds=2)
        db_session.commit()

        response = client.get(f"/api/workflows/{wf_id}/audit")
        assert response.status_code == 200
        data = response.json()

        assert len(data) == 3
        assert data[0]["event_type"] == AuditEventType.SCAN_STARTED.value
        assert data[1]["event_type"] == AuditEventType.SCAN_COMPLETED.value
        assert data[2]["event_type"] == AuditEventType.RISK_ASSESSMENT_STARTED.value

    def test_audit_filters_work(self, client: TestClient, db_session: Session):
        """10. Verify GET /api/audit/events filtering by parameters."""
        service = AuditService()
        service.record_event(
            event_type=AuditEventType.SCAN_STARTED,
            workflow_id="wf-filter-A",
            session=db_session,
        )
        service.record_event(
            event_type=AuditEventType.PATCH_GENERATED,
            workflow_id="wf-filter-B",
            vulnerability_id="VULN-B",
            session=db_session,
        )
        db_session.commit()

        # Filter by workflow_id
        res_a = client.get("/api/audit/events?workflow_id=wf-filter-A")
        assert res_a.status_code == 200
        data_a = res_a.json()
        assert len(data_a) == 1
        assert data_a[0]["workflow_id"] == "wf-filter-A"

        # Filter by event_type
        res_type = client.get("/api/audit/events?event_type=PATCH_GENERATED")
        assert res_type.status_code == 200
        data_type = res_type.json()
        assert len(data_type) == 1
        assert data_type[0]["event_type"] == "PATCH_GENERATED"

    def test_pagination_works(self, client: TestClient, db_session: Session):
        """11. Verify limit and offset pagination on /api/audit/events."""
        service = AuditService()
        wf_id = "wf-pagination-test"
        for i in range(5):
            service.record_event(
                event_type=AuditEventType.PATCH_VALIDATION_STARTED,
                workflow_id=wf_id,
                message=f"Event #{i}",
                session=db_session,
            )
        db_session.commit()

        res = client.get(f"/api/audit/events?workflow_id={wf_id}&limit=2&offset=0")
        assert res.status_code == 200
        page1 = res.json()
        assert len(page1) == 2

        res2 = client.get(f"/api/audit/events?workflow_id={wf_id}&limit=2&offset=2")
        assert res2.status_code == 200
        page2 = res2.json()
        assert len(page2) == 2
        assert page1[0]["id"] != page2[0]["id"]

    def test_audit_records_persist_after_session_close(self, db_session: Session):
        """12. Verify audit records persist in SQLite across session lifecycles."""
        service = AuditService()
        event = service.record_event(
            event_type=AuditEventType.READY_FOR_REVIEW,
            workflow_id="wf-persist-check",
            message="Milestone ready for review",
            metadata={"reviewer": "sec-ops"},
            session=db_session,
        )
        db_session.commit()
        event_id = event.id

        # Verify query in a brand-new database session
        new_session = Session(bind=db_session.get_bind())
        try:
            fetched = service.get_event(event_id, session=new_session)
            assert fetched is not None
            assert fetched.id == event_id
            assert fetched.event_type == AuditEventType.READY_FOR_REVIEW.value
            assert fetched.get_metadata()["reviewer"] == "sec-ops"
        finally:
            new_session.close()
