"""Bounded local background orchestration with a fresh session per job."""
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from backend.config import get_settings
from backend.database.database import SessionLocal
from backend.database.models import WorkflowModel, VulnerabilityModel, utc_now
from backend.agents.scanning_agent import ScanningAgent
from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.agents.retry_agent import RetryAgent
from backend.services.audit import AuditService
from backend.services.repository import RepositoryService

ACTIVE_STATES = {"CREATED", "SCANNING", "RISK_ASSESSMENT", "PATCH_GENERATION", "VALIDATING", "RETRYING"}


def validate_repository(path):
    settings = get_settings()
    root = getattr(settings, "ALLOWED_REPOSITORY_ROOT", None) or str(Path.cwd())
    return RepositoryService(allowed_base_dir=root).validate_repository_path(path)


class WorkflowRunner:
    def __init__(self, scanner=None, risk=None, generator=None, retry=None):
        self.scanner = scanner or ScanningAgent()
        self.risk = risk or RiskAssessmentAgent()
        self.generator = generator or PatchGenerationAgent()
        self.retry = retry or RetryAgent(patch_generation_agent=self.generator)

    def run(self, db, workflow_id):
        wf = db.get(WorkflowModel, workflow_id)
        if not wf or wf.status != "CREATED":
            return
        errors = []
        def stage(value):
            wf.status = value
            wf.current_stage = value
            AuditService().record_event("WORKFLOW_STAGE", workflow_id=wf.id, message=value, session=db)
            db.commit()
        def finish(status, outcome):
            wf.status = status
            wf.current_stage = "FINISHED"
            wf.outcome = outcome
            wf.completed_at = utc_now()
            wf.errors_json = json.dumps(errors)
            wf.error_message = "; ".join(errors) or None
            AuditService().record_event("WORKFLOW_FINISHED", workflow_id=wf.id, message=outcome, session=db)
            db.commit()
        try:
            wf.started_at = utc_now()
            stage("SCANNING")
            findings, metadata = self.scanner.scan(wf.repository_path, workflow_id=wf.id, persist=True, db_session=db, manage_workflow=False)
            wf.scan_metadata = json.dumps(metadata)
            wf.total_findings = len(findings)
            db.commit()
            if metadata.get("scan_status") != "COMPLETED" or metadata.get("coverage_complete") is not True:
                errors.extend(metadata.get("errors") or ["Complete scanner coverage unavailable"])
                finish("FAILED", "SCAN_INCONCLUSIVE")
                return
            if not findings:
                finish("COMPLETED", "NO_FINDINGS")
                return
            stage("RISK_ASSESSMENT")
            ranked = self.risk.assess_workflow(wf.id, persist=True, db_session=db)
            policy = json.loads(wf.request_json or "{}")
            weights = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            selected = [item for item in ranked if weights[str(item.risk_assessment.priority.value)] >= weights[policy.get("minimum_priority", "LOW")]][:policy.get("max_findings", 10)]
            for item in selected:
                finding_id = item.vulnerability.id
                try:
                    stage("PATCH_GENERATION")
                    candidate = self.generator.generate_patch_for_vulnerability_id(finding_id, persist=True, db_session=db)
                    if candidate.status.value in {"FAILED", "REJECTED"}:
                        raise ValueError("Candidate generation rejected: " + candidate.explanation)
                    stage("VALIDATING")
                    result = self.retry.run_retry_loop(candidate.id, max_retries=wf.max_retries, db_session=db)
                    if result.successful_patch_id:
                        wf.reviewable_count += 1
                    else:
                        raise ValueError(result.final_failure_reason or result.status)
                except Exception as error:
                    db.rollback()
                    wf = db.get(WorkflowModel, workflow_id)
                    wf.failed_count += 1
                    errors.append(f"{finding_id}: {error}")
                    finding = db.get(VulnerabilityModel, finding_id)
                    if finding:
                        finding.status = "UNRESOLVED"
                wf.processed_findings += 1
                wf.errors_json = json.dumps(errors)
                db.commit()
            omitted = wf.total_findings - wf.processed_findings
            if wf.reviewable_count:
                outcome = "PARTIAL_SUCCESS" if wf.failed_count or omitted else "REVIEWABLE"
                finish("READY_FOR_REVIEW", outcome)
            elif not selected:
                finish("COMPLETED", "NO_ELIGIBLE_FINDINGS")
            else:
                finish("FAILED", "REMEDIATION_FAILED")
        except Exception as error:
            db.rollback()
            wf = db.get(WorkflowModel, workflow_id)
            errors.append(str(error))
            finish("FAILED", "WORKFLOW_ERROR")


class WorkflowJobs:
    def __init__(self, session_factory=SessionLocal, runner_factory=WorkflowRunner, workers=2, capacity=8):
        self.session_factory = session_factory
        self.runner_factory = runner_factory
        self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="autopatch")
        self.slots = threading.BoundedSemaphore(capacity)
        self.lock = threading.Lock()
        self.active = set()

    def submit(self, workflow_id):
        with self.lock:
            if workflow_id in self.active:
                return False
            if not self.slots.acquire(blocking=False):
                raise RuntimeError("Workflow capacity reached; retry after a job finishes")
            self.active.add(workflow_id)
        def job():
            try:
                with self.session_factory() as db:
                    try:
                        self.runner_factory().run(db, workflow_id)
                    except Exception as error:
                        db.rollback()
                        wf = db.get(WorkflowModel, workflow_id)
                        if wf:
                            wf.status = "FAILED"
                            wf.outcome = "WORKFLOW_ERROR"
                            wf.current_stage = "FINISHED"
                            wf.completed_at = utc_now()
                            wf.error_message = str(error)
                            wf.errors_json = json.dumps([str(error)])
                            db.commit()
            finally:
                with self.lock:
                    self.active.discard(workflow_id)
                self.slots.release()
        try:
            self.executor.submit(job)
        except Exception:
            with self.lock:
                self.active.discard(workflow_id)
            self.slots.release()
            raise
        return True

    def recover(self):
        with self.session_factory() as db:
            for wf in db.query(WorkflowModel).filter(WorkflowModel.status.in_(ACTIVE_STATES)).all():
                wf.status = "FAILED"
                wf.current_stage = "INTERRUPTED"
                wf.outcome = "INTERRUPTED"
                wf.completed_at = utc_now()
                wf.error_message = "Application stopped before this local background job completed; submit a new workflow"
                wf.errors_json = json.dumps([wf.error_message])
                AuditService().record_event("WORKFLOW_INTERRUPTED", workflow_id=wf.id, message=wf.error_message, session=db)
            db.commit()

    def shutdown(self):
        self.executor.shutdown(wait=True)

    def start(self):
        """Allow repeated application lifespans without reusing a stopped pool."""
        if self.executor._shutdown:
            self.executor = ThreadPoolExecutor(max_workers=self.executor._max_workers, thread_name_prefix="autopatch")


workflow_jobs = WorkflowJobs(workers=get_settings().WORKFLOW_WORKERS, capacity=get_settings().WORKFLOW_QUEUE_LIMIT)
