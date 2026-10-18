"""AutoPatch Validation Agent.

Orchestrates candidate patch validation in isolated temporary workspaces or secure Docker sandboxes.
Applies candidate patches, performs syntax and build verification inside the sandbox,
executes project test suites via TestRunner, re-runs static security scanners (Bandit, Semgrep),
compares findings to verify vulnerability mitigation without functional or security regressions,
verifies original repository immutability (SHA-256), and persists validation verdicts to SQLite.
"""

import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Optional

from backend.config import get_settings
from backend.database.database import session_scope
from backend.database.models import (
    PatchAttemptModel,
    RiskAssessmentModel,
    ValidationResultModel,
    VulnerabilityModel,
    WorkflowModel,
    utc_now,
)
from backend.models.audit import AuditEventStatus, AuditEventType
from backend.models.patch import PatchGenerationResult, PatchStatus
from backend.models.retry import FailureCategory
from backend.models.validation import (
    SecurityComparisonResult,
    ValidationResult,
    ValidationStatus,
)
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
)
from backend.services.audit import AuditService
from backend.agents.scanning_agent import ScanningAgent
from backend.tools.bandit_runner import BanditRunner
from backend.tools.patch_applier import PatchApplier
from backend.tools.sandbox import (
    DockerRequiredError,
    LocalWorkspaceSandboxExecutor,
    SandboxExecutor,
    get_default_sandbox_executor,
)
from backend.tools.semgrep_runner import SemgrepRunner
from backend.tools.test_runner import TestResult, TestRunner
from backend.tools.workspace import TemporaryWorkspace

logger = logging.getLogger(__name__)


class PatchLifecycleConflict(ValueError):
    """A review decision prevents further candidate mutation."""


class ValidationAgent:
    """Specialized Agent responsible for verifying candidate security patches in isolated sandboxes."""

    def __init__(
        self,
        test_runner: Optional[TestRunner] = None,
        patch_applier: Optional[PatchApplier] = None,
        bandit_runner: Optional[BanditRunner] = None,
        semgrep_runner: Optional[SemgrepRunner] = None,
        scanning_agent: Optional[ScanningAgent] = None,
        sandbox: Optional[SandboxExecutor] = None,
        test_timeout: Optional[int] = None,
        audit_service: Optional[AuditService] = None,
    ):
        """
        Initialize Validation Agent.

        :param test_runner: Dedicated test execution tool.
        :param patch_applier: Pure-Python patch application service.
        :param bandit_runner: Optional BanditRunner instance.
        :param semgrep_runner: Optional SemgrepRunner instance.
        :param scanning_agent: Optional ScanningAgent instance.
        :param sandbox: Optional SandboxExecutor (Docker or local workspace fallback).
        :param test_timeout: Test execution timeout in seconds.
        """
        settings = get_settings()
        self.test_timeout = test_timeout or settings.TEST_TIMEOUT
        self.sandbox = sandbox or get_default_sandbox_executor()
        self.test_runner = test_runner or TestRunner(timeout=self.test_timeout, sandbox=self.sandbox)
        self.patch_applier = patch_applier or PatchApplier()
        self.bandit_runner = bandit_runner or BanditRunner(sandbox=self.sandbox)
        self.semgrep_runner = semgrep_runner or SemgrepRunner(sandbox=self.sandbox)
        self.scanning_agent = scanning_agent or ScanningAgent(
            bandit_runner=self.bandit_runner,
            semgrep_runner=self.semgrep_runner,
        )
        self.audit_service = audit_service or AuditService()

    def _run_syntax_check(self, workspace_path: Path) -> tuple[bool, str]:
        """
        Run controlled Python bytecode compilation check across workspace files inside the sandbox.
        Never uses shell=True.
        """
        if self.sandbox.sandbox_type == "docker":
            cmd = ["python", "-m", "compileall", "-q", "."]
        else:
            cmd = [sys.executable, "-m", "compileall", "-q", str(workspace_path)]

        try:
            exec_res = self.sandbox.run_command(cmd, cwd=workspace_path, timeout=30)
            if exec_res.exit_code == 0 and not exec_res.timed_out:
                return True, "Syntax compilation succeeded."
            return False, exec_res.stderr or exec_res.stdout or "Syntax compilation failed."
        except Exception as e:
            return False, f"Syntax check invocation error: {str(e)}"

    @staticmethod
    def _calculate_repo_hashes(repo_path: str | Path) -> dict[str, str]:
        """Compute SHA-256 hash map of all regular files in repository to verify immutability."""
        path = Path(repo_path).resolve()
        hashes = {}
        if not path.exists() or not path.is_dir():
            return hashes
        for p in sorted(path.rglob("*")):
            if p.is_file() and not p.is_symlink():
                # Exclude temporary/cache directories
                if any(part in (".git", ".hg", ".svn", ".pytest_cache", "__pycache__", "venv", ".venv", ".venv-runtime", ".test-artifacts", ".test-tmp", "node_modules") for part in p.relative_to(path).parts):
                    continue
                try:
                    rel = str(p.relative_to(path)).replace("\\", "/")
                    hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
                except Exception:
                    pass
        return hashes

    def _compare_security_findings(
        self,
        original_finding: VulnerabilityFinding,
        baseline_findings: list[VulnerabilityFinding],
        rescan_findings: list[VulnerabilityFinding],
    ) -> SecurityComparisonResult:
        """
        Compare security findings before and after patching to determine if
        the original vulnerability was mitigated and if new findings were introduced.
        Matches findings using stable identity attributes (tool, rule_id, CWE, type, file_path)
        rather than volatile line numbers.
        """
        def _identity_match(f: VulnerabilityFinding, target: VulnerabilityFinding) -> bool:
            # File path match (relative or suffix)
            f1 = f.file_path.replace("\\", "/").strip()
            f2 = target.file_path.replace("\\", "/").strip()
            file_matches = (f1 == f2)

            if not file_matches:
                return False

            # Same tool
            if f.tool != target.tool:
                return False

            # If both have rule_id, rule_id MUST match!
            if f.rule_id and target.rule_id:
                if f.rule_id != target.rule_id:
                    return False
                # If target has line information, check proximity (±15 lines) to avoid conflating distant occurrences
                if target.line_start is not None and f.line_start is not None:
                    return abs(target.line_start - f.line_start) <= 15
                return True

            # If rule_id is absent, check CWE or Type with line proximity
            if f.cwe and target.cwe and f.cwe == target.cwe:
                if target.line_start is not None and f.line_start is not None:
                    return abs(target.line_start - f.line_start) <= 15
                return True

            if f.type and target.type and f.type.lower() == target.type.lower():
                if target.line_start is not None and f.line_start is not None:
                    return abs(target.line_start - f.line_start) <= 15
                return True

            return False

        def _is_match(f: VulnerabilityFinding, target: VulnerabilityFinding) -> bool:
            def identities(finding):
                raw = finding.raw_finding if isinstance(finding.raw_finding, dict) else {}
                provenance = raw.get("_autopatch_provenance")
                if isinstance(provenance, list) and provenance:
                    return [finding.model_copy(update=item) for item in provenance if isinstance(item, dict)]
                # Legacy merged records retain only the first rule identity. Conservatively
                # match shared tool and CWE when one scanner's old identity is unavailable.
                return [finding]
            for left in identities(f):
                for right in identities(target):
                    if _identity_match(left, right):
                        return True
                    left_tools = set(left.tool.split(", "))
                    right_tools = set(right.tool.split(", "))
                    if (len(left_tools) > 1 or len(right_tools) > 1) and left_tools & right_tools:
                        if left.file_path == right.file_path and left.cwe and left.cwe == right.cwe:
                            if left.line_start is None or right.line_start is None or abs(left.line_start-right.line_start) <= 15:
                                return True
            return False

        # Check if original vulnerability remains
        remaining_matches = [f for f in rescan_findings if _is_match(f, original_finding)]
        orig_resolved = (len(remaining_matches) == 0)

        # Detect newly introduced findings: not present in baseline scan
        new_findings: list[VulnerabilityFinding] = []
        for rf in rescan_findings:
            matched_in_baseline = any(_is_match(rf, bf) for bf in baseline_findings)
            if not matched_in_baseline:
                new_findings.append(rf)

        security_scan_passed = orig_resolved and (len(new_findings) == 0)

        return SecurityComparisonResult(
            original_vulnerability_resolved=orig_resolved,
            remaining_original_findings_count=len(remaining_matches),
            new_findings_count=len(new_findings),
            new_findings=[f.model_dump(mode="json") for f in new_findings],
            security_scan_passed=security_scan_passed,
        )

    def validate_patch(
        self,
        patch_id: str,
        persist: bool = True,
        db_session: Optional[Any] = None,
    ) -> ValidationResult:
        """
        Execute full isolated validation pipeline for a candidate patch attempt.

        :param patch_id: ID of the PatchAttempt record in database.
        :param persist: Whether to save validation result to database.
        :param db_session: Optional active SQLAlchemy session.
        :return: ValidationResult model.
        """
        patch_record: Optional[PatchAttemptModel] = None
        vuln_record: Optional[VulnerabilityModel] = None
        repo_path: Optional[str] = None
        all_vuln_records: list[VulnerabilityModel] = []

        def _fetch(session):
            nonlocal patch_record, vuln_record, repo_path, all_vuln_records
            patch_record = session.query(PatchAttemptModel).filter(PatchAttemptModel.id == patch_id).first()
            if not patch_record:
                raise ValueError(f"Patch attempt '{patch_id}' not found.")
            if patch_record.status in {PatchStatus.REJECTED.value, PatchStatus.APPROVED.value}:
                raise PatchLifecycleConflict("Reviewed candidates cannot be validated again.")
            if patch_record.status == PatchStatus.FAILED.value or not patch_record.patch_content:
                raise ValueError("Patch is not eligible for validation; inspect its generation or review status.")

            vuln_record = session.query(VulnerabilityModel).filter(
                VulnerabilityModel.id == patch_record.vulnerability_id
            ).first()
            if not vuln_record:
                raise ValueError(f"Vulnerability '{patch_record.vulnerability_id}' not found.")

            risk_rec = session.query(RiskAssessmentModel).filter(
                RiskAssessmentModel.vulnerability_id == vuln_record.id
            ).first()
            if not risk_rec:
                raise ValueError(f"No risk assessment found for vulnerability '{vuln_record.id}'.")

            wf = session.query(WorkflowModel).filter(WorkflowModel.id == patch_record.workflow_id).first()
            if not wf or not wf.repository_path:
                raise ValueError(f"Workflow '{patch_record.workflow_id}' repository path not found.")

            repo_path = wf.repository_path
            all_vuln_records = session.query(VulnerabilityModel).filter(
                VulnerabilityModel.workflow_id == patch_record.workflow_id
            ).all()

        if db_session is not None:
            _fetch(db_session)
        else:
            with session_scope() as session:
                _fetch(session)

        original_finding = VulnerabilityFinding(
            id=vuln_record.id,
            workflow_id=vuln_record.workflow_id,
            tool=vuln_record.tool,
            rule_id=vuln_record.rule_id,
            type=vuln_record.type,
            cwe=vuln_record.cwe,
            severity=Severity(vuln_record.severity) if vuln_record.severity in Severity.__members__ else Severity.MEDIUM,
            confidence=Confidence(vuln_record.confidence) if vuln_record.confidence and vuln_record.confidence in Confidence.__members__ else None,
            file_path=vuln_record.file_path,
            line_start=vuln_record.line_start,
            line_end=vuln_record.line_end,
            code_snippet=vuln_record.code_snippet,
            description=vuln_record.description,
            raw_finding=vuln_record.get_raw_finding(),
            status=VulnerabilityStatus(vuln_record.status) if vuln_record.status in VulnerabilityStatus.__members__ else VulnerabilityStatus.PRIORITIZED,
        )

        baseline_findings = [
            VulnerabilityFinding(
                id=vr.id,
                workflow_id=vr.workflow_id,
                tool=vr.tool,
                rule_id=vr.rule_id,
                type=vr.type,
                cwe=vr.cwe,
                severity=Severity(vr.severity) if vr.severity in Severity.__members__ else Severity.MEDIUM,
                confidence=Confidence(vr.confidence) if vr.confidence and vr.confidence in Confidence.__members__ else None,
                file_path=vr.file_path,
                line_start=vr.line_start,
                line_end=vr.line_end,
                code_snippet=vr.code_snippet,
                description=vr.description,
                raw_finding=vr.get_raw_finding(),
                status=VulnerabilityStatus(vr.status) if vr.status in VulnerabilityStatus.__members__ else VulnerabilityStatus.PRIORITIZED,
            )
            for vr in all_vuln_records
        ]

        return self.execute_validation(
            patch_id=patch_id,
            vulnerability=original_finding,
            unified_diff=patch_record.patch_content,
            repository_path=repo_path,
            workflow_id=patch_record.workflow_id,
            baseline_findings=baseline_findings,
            persist=persist,
            db_session=db_session,
        )

    def execute_validation(
        self,
        patch_id: str,
        vulnerability: VulnerabilityFinding,
        unified_diff: str,
        repository_path: str | Path,
        workflow_id: Optional[str] = None,
        baseline_findings: Optional[list[VulnerabilityFinding]] = None,
        persist: bool = True,
        db_session: Optional[Any] = None,
    ) -> ValidationResult:
        """
        Execute isolated candidate patch validation against a repository copy.
        Verifies original repository immutability (SHA-256) before and after execution.

        :param patch_id: Identifier of the patch attempt being tested.
        :param vulnerability: Original VulnerabilityFinding being mitigated.
        :param unified_diff: Candidate unified diff content to apply and verify.
        :param repository_path: Canonical source repository path.
        :param workflow_id: Associated workflow run identifier.
        :param baseline_findings: Pre-existing findings from workflow scan.
        :param persist: Whether to persist results to the database.
        :param db_session: Optional active SQLAlchemy session.
        :return: ValidationResult model.
        """
        start_time = time.perf_counter()
        start_utc = utc_now()
        val_id = f"VAL-{hashlib.sha256(f'{patch_id}:{start_utc.isoformat()}'.encode('utf-8')).hexdigest()[:8].upper()}"

        logger.info(
            "Starting validation run %s for patch %s (Sandbox: %s, Vuln: %s, Repo: %s)",
            val_id,
            patch_id,
            self.sandbox.sandbox_type,
            vulnerability.id,
            repository_path,
        )

        validation_logs: list[str] = []
        validation_logs.append(f"Validation initialized for patch {patch_id} at {start_utc.isoformat()}.")
        validation_logs.append(f"Configured sandbox type: {self.sandbox.sandbox_type}.")

        if persist:
            self.audit_service.record_event(
                event_type=AuditEventType.PATCH_VALIDATION_STARTED,
                workflow_id=workflow_id,
                vulnerability_id=vulnerability.id,
                patch_attempt_id=patch_id,
                validation_id=val_id,
                event_status=AuditEventStatus.INFO,
                message=f"Validation initiated for patch {patch_id} (Sandbox: {self.sandbox.sandbox_type}).",
                metadata={"sandbox_type": self.sandbox.sandbox_type},
                session=db_session,
            )

        # Initial state machine tracking
        patch_applied = False
        syntax_passed = False
        tests_passed = False
        sec_scan_passed = False
        orig_resolved = False
        regression_detected = False
        failure_reason = None
        test_result: Optional[TestResult] = None
        new_findings: list[dict[str, Any]] = []
        scanner_metadata: dict[str, Any] = {}

        # Step 0: Calculate initial SHA-256 hashes of original repository (Immutability guarantee)
        initial_repo_hashes = self._calculate_repo_hashes(repository_path)

        # Step 1: Update Patch Attempt Status to VALIDATING
        if persist:
            self._update_patch_status(patch_id, PatchStatus.VALIDATING.value, db_session=db_session)

        # Step 2: Spawn Isolated Temporary Workspace
        try:
            with TemporaryWorkspace(repository_path) as workspace:
                validation_logs.append(f"Spawned isolated temporary workspace at '{workspace}'.")

                # Step 3: Apply Candidate Patch to Workspace Atomically
                applied, apply_err = self.patch_applier.apply_patch(workspace, unified_diff)
                if not applied:
                    patch_applied = False
                    failure_reason = f"Patch application failed: {apply_err}"
                    validation_logs.append(f"ERROR: {failure_reason}")
                    return self._finalize_and_verify_immutability(
                        val_id=val_id,
                        patch_id=patch_id,
                        vulnerability=vulnerability,
                        workflow_id=workflow_id,
                        status=ValidationStatus.FAILED,
                        patch_applied=False,
                        syntax_passed=False,
                        tests_passed=False,
                        sec_scan_passed=False,
                        orig_resolved=False,
                        regression=True,
                        failure_reason=failure_reason,
                        failure_category=FailureCategory.PATCH_APPLICATION_FAILED.value,
                        validation_logs="\n".join(validation_logs),
                        duration=time.perf_counter() - start_time,
                        started_at=start_utc,
                        repository_path=repository_path,
                        initial_hashes=initial_repo_hashes,
                        persist=persist,
                        db_session=db_session,
                    )

                patch_applied = True
                validation_logs.append("Candidate patch applied cleanly to workspace.")
                if persist:
                    self.audit_service.record_event(
                        event_type=AuditEventType.PATCH_APPLIED,
                        workflow_id=workflow_id,
                        vulnerability_id=vulnerability.id,
                        patch_attempt_id=patch_id,
                        validation_id=val_id,
                        event_status=AuditEventStatus.SUCCESS,
                        message=f"Candidate patch {patch_id} applied cleanly to workspace.",
                        metadata={"sandbox_type": self.sandbox.sandbox_type},
                        session=db_session,
                    )

                # Step 4: Syntax / Compilation Verification via Sandbox
                syn_ok, syn_msg = self._run_syntax_check(workspace)
                if not syn_ok:
                    syntax_passed = False
                    failure_reason = f"Syntax check failed: {syn_msg}"
                    validation_logs.append(f"ERROR: {failure_reason}")
                    return self._finalize_and_verify_immutability(
                        val_id=val_id,
                        patch_id=patch_id,
                        vulnerability=vulnerability,
                        workflow_id=workflow_id,
                        status=ValidationStatus.FAILED,
                        patch_applied=True,
                        syntax_passed=False,
                        tests_passed=False,
                        sec_scan_passed=False,
                        orig_resolved=False,
                        regression=True,
                        failure_reason=failure_reason,
                        failure_category=FailureCategory.SYNTAX_ERROR.value,
                        validation_logs="\n".join(validation_logs),
                        duration=time.perf_counter() - start_time,
                        started_at=start_utc,
                        repository_path=repository_path,
                        initial_hashes=initial_repo_hashes,
                        persist=persist,
                        db_session=db_session,
                    )

                syntax_passed = True
                validation_logs.append("Syntax compilation check passed cleanly inside sandbox.")

                # Step 5: Execute Test Suite via Sandbox
                test_result = self.test_runner.run_tests(workspace)
                tests_passed = test_result.success
                validation_logs.append(
                    f"Test execution finished (Exit: {test_result.exit_code}, "
                    f"Passed: {test_result.tests_passed}, Failed: {test_result.tests_failed}, "
                    f"Skipped: {test_result.tests_skipped}, Duration: {test_result.duration}s)."
                )

                if not tests_passed:
                    regression_detected = True
                    failure_reason = test_result.error_message or "Project test suite failed after patch application."
                    validation_logs.append(f"WARNING: Tests failed: {failure_reason}")

                # Step 6: Security Re-Scan with Bandit & Semgrep on temporary workspace
                validation_logs.append("Executing security re-scan with Bandit and Semgrep...")
                scan_fn = getattr(self.scanning_agent, "scan", None) or getattr(self.scanning_agent, "scan_repository", None)
                if not scan_fn:
                    raise AttributeError("ScanningAgent must implement 'scan' or 'scan_repository'.")
                rescan_findings, scan_meta = scan_fn(
                    repository_path=workspace,
                    persist=False,
                )
                scan_status = scan_meta.get("scan_status", "UNKNOWN")
                scanner_metadata = scan_meta
                validation_logs.append(
                    f"Security re-scan completed with status '{scan_status}', "
                    f"findings count: {len(rescan_findings)}."
                )

                if scan_status != "COMPLETED" or scan_meta.get("coverage_complete") is not True:
                    failure_reason = failure_reason or f"Security re-scan failed: {'; '.join(scan_meta.get('errors', ['Scanners failed']))}"
                    validation_logs.append(f"ERROR: {failure_reason}")

                # Step 7: Differential Finding Comparison
                baseline = baseline_findings if baseline_findings is not None else [vulnerability]
                comparison = self._compare_security_findings(
                    original_finding=vulnerability,
                    baseline_findings=baseline,
                    rescan_findings=rescan_findings,
                )

                orig_resolved = comparison.original_vulnerability_resolved
                sec_scan_passed = comparison.security_scan_passed
                new_findings = comparison.new_findings

                if scan_status != "COMPLETED" or scan_meta.get("coverage_complete") is not True:
                    orig_resolved = False
                    sec_scan_passed = False

                if not orig_resolved:
                    failure_reason = failure_reason or f"Original vulnerability '{vulnerability.id}' ({vulnerability.type}) is still detected."
                    validation_logs.append(f"WARNING: Vulnerability not resolved: {vulnerability.id} is still detected.")
                else:
                    validation_logs.append(f"CONFIRMED: Original vulnerability '{vulnerability.id}' is successfully resolved.")

                if comparison.new_findings_count > 0:
                    regression_detected = True
                    sec_scan_passed = False
                    failure_reason = failure_reason or f"Patch introduced {comparison.new_findings_count} new security finding(s)."
                    validation_logs.append(f"WARNING: Introduced new security findings: {comparison.new_findings_count}.")

                # Step 8: Strict Final State Machine Verdict
                is_all_passed = (
                    patch_applied
                    and syntax_passed
                    and tests_passed
                    and orig_resolved
                    and sec_scan_passed
                    and not regression_detected
                )

                incomplete_scan = scan_status != "COMPLETED" or scan_meta.get("coverage_complete") is not True
                overall_status = ValidationStatus.ERROR if incomplete_scan else (ValidationStatus.PASSED if is_all_passed else ValidationStatus.FAILED)
                verdict_category: Optional[str] = None
                if overall_status == ValidationStatus.PASSED:
                    validation_logs.append("VALIDATION SUCCESS: Patch met all correctness, testing, and security criteria.")
                else:
                    validation_logs.append(f"VALIDATION FAILED: {failure_reason}")
                    test_output = (test_result.stdout or "") + "\n" + (test_result.stderr or "") if test_result else ""
                    missing_dependency = "ModuleNotFoundError" in test_output or "No module named" in test_output
                    if missing_dependency:
                        overall_status = ValidationStatus.ERROR
                        failure_reason = "Validation environment is missing a project dependency; prepare a trusted validator image before retrying."
                        verdict_category = FailureCategory.INFRASTRUCTURE_FAILURE.value
                    elif incomplete_scan:
                        verdict_category = FailureCategory.INFRASTRUCTURE_FAILURE.value
                    elif not tests_passed:
                        verdict_category = FailureCategory.TEST_FAILURE.value
                    elif scan_status == "FAILED":
                        verdict_category = FailureCategory.INFRASTRUCTURE_FAILURE.value
                    elif not orig_resolved:
                        verdict_category = FailureCategory.UNRESOLVED_VULNERABILITY.value
                    elif comparison.new_findings_count > 0:
                        verdict_category = FailureCategory.NEW_VULNERABILITY.value
                    elif regression_detected or not sec_scan_passed:
                        verdict_category = FailureCategory.SECURITY_REGRESSION.value
                    else:
                        verdict_category = FailureCategory.UNKNOWN_FAILURE.value

                return self._finalize_and_verify_immutability(
                    val_id=val_id,
                    patch_id=patch_id,
                    vulnerability=vulnerability,
                    workflow_id=workflow_id,
                    status=overall_status,
                    patch_applied=patch_applied,
                    syntax_passed=syntax_passed,
                    tests_passed=tests_passed,
                    sec_scan_passed=sec_scan_passed,
                    orig_resolved=orig_resolved,
                    regression=regression_detected,
                    failure_reason=failure_reason,
                    failure_category=verdict_category,
                    validation_logs="\n".join(validation_logs),
                    duration=time.perf_counter() - start_time,
                    started_at=start_utc,
                    test_result=test_result,
                    new_findings=new_findings,
                    scanner_metadata=scanner_metadata,
                    repository_path=repository_path,
                    initial_hashes=initial_repo_hashes,
                    persist=persist,
                    db_session=db_session,
                )

        except DockerRequiredError as e:
            logger.error("Docker execution required but failed closed: %s", e)
            return self._finalize_and_verify_immutability(
                val_id=val_id,
                patch_id=patch_id,
                vulnerability=vulnerability,
                workflow_id=workflow_id,
                status=ValidationStatus.ERROR,
                patch_applied=patch_applied,
                syntax_passed=syntax_passed,
                tests_passed=False,
                sec_scan_passed=False,
                orig_resolved=False,
                regression=True,
                failure_reason=f"Docker sandbox required but unavailable: {str(e)}",
                failure_category=FailureCategory.DOCKER_UNAVAILABLE.value,
                validation_logs=f"Docker error: {str(e)}",
                duration=time.perf_counter() - start_time,
                started_at=start_utc,
                repository_path=repository_path,
                initial_hashes=initial_repo_hashes,
                persist=persist,
                db_session=db_session,
            )

        except Exception as e:
            logger.error("Unexpected error during validation run %s: %s", val_id, e)
            return self._finalize_and_verify_immutability(
                val_id=val_id,
                patch_id=patch_id,
                vulnerability=vulnerability,
                workflow_id=workflow_id,
                status=ValidationStatus.ERROR,
                patch_applied=patch_applied,
                syntax_passed=syntax_passed,
                tests_passed=False,
                sec_scan_passed=False,
                orig_resolved=False,
                regression=True,
                failure_reason=f"Validation runtime exception: {str(e)}",
                failure_category=FailureCategory.INFRASTRUCTURE_FAILURE.value,
                validation_logs=f"Runtime error: {str(e)}",
                duration=time.perf_counter() - start_time,
                started_at=start_utc,
                repository_path=repository_path,
                initial_hashes=initial_repo_hashes,
                persist=persist,
                db_session=db_session,
            )

    def _update_patch_status(self, patch_id: str, new_status: str, db_session: Optional[Any] = None) -> None:
        """Update patch attempt status in the database."""
        def _do(session):
            query = session.query(PatchAttemptModel).filter(PatchAttemptModel.id == patch_id)
            changed = query.filter(PatchAttemptModel.status.notin_(["APPROVED", "REJECTED"])).update(
                {PatchAttemptModel.status: new_status}, synchronize_session="fetch")
            if not changed and query.first() is not None:
                raise PatchLifecycleConflict("Review was recorded; candidate state is immutable.")

        if db_session is not None:
            _do(db_session)
            db_session.commit()
        else:
            with session_scope() as session:
                _do(session)

    def _finalize_and_verify_immutability(
        self,
        val_id: str,
        patch_id: str,
        vulnerability: VulnerabilityFinding,
        workflow_id: Optional[str],
        status: ValidationStatus,
        patch_applied: bool,
        syntax_passed: bool,
        tests_passed: bool,
        sec_scan_passed: bool,
        orig_resolved: bool,
        regression: bool,
        failure_reason: Optional[str],
        validation_logs: str,
        duration: float,
        started_at: Any,
        repository_path: str | Path,
        initial_hashes: dict[str, str],
        failure_category: Optional[str] = None,
        test_result: Optional[TestResult] = None,
        new_findings: Optional[list[dict[str, Any]]] = None,
        scanner_metadata: Optional[dict[str, Any]] = None,
        persist: bool = True,
        db_session: Optional[Any] = None,
    ) -> ValidationResult:
        """
        Verify that original repository files were not modified during validation,
        construct domain model, update status transitions, and persist ValidationResultModel.
        """
        # Original Repository Immutability Check (Part 16)
        final_hashes = self._calculate_repo_hashes(repository_path)
        computed_category: Optional[str] = None

        if initial_hashes != final_hashes:
            logger.critical("CRITICAL: Original repository '%s' was mutated during validation!", repository_path)
            status = ValidationStatus.ERROR
            regression = True
            failure_reason = "CRITICAL SECURITY VIOLATION: Original repository was modified during validation."
            validation_logs += "\nCRITICAL ERROR: Original repository contents changed!"
            computed_category = FailureCategory.SECURITY_REGRESSION.value
        elif status == ValidationStatus.PASSED:
            computed_category = None
        elif failure_category:
            computed_category = failure_category
        elif not patch_applied:
            computed_category = FailureCategory.PATCH_APPLICATION_FAILED.value
        elif not syntax_passed:
            computed_category = FailureCategory.SYNTAX_ERROR.value
        elif not tests_passed:
            computed_category = FailureCategory.TEST_FAILURE.value
        elif failure_reason and ("security re-scan failed" in failure_reason.lower() or "scanner" in failure_reason.lower()):
            computed_category = FailureCategory.INFRASTRUCTURE_FAILURE.value
        elif not orig_resolved:
            computed_category = FailureCategory.UNRESOLVED_VULNERABILITY.value
        elif new_findings and len(new_findings) > 0:
            computed_category = FailureCategory.NEW_VULNERABILITY.value
        elif regression or not sec_scan_passed:
            computed_category = FailureCategory.SECURITY_REGRESSION.value
        else:
            computed_category = FailureCategory.UNKNOWN_FAILURE.value

        completed_at = utc_now()
        new_findings_list = new_findings or []

        # Tests run includes all tests that were executed (passed + failed)
        tests_run_count = test_result.tests_run if test_result else 0

        sandbox_type = self.sandbox.sandbox_type if self.sandbox else "local_workspace_dev_fallback"

        result = ValidationResult(
            id=val_id,
            patch_attempt_id=patch_id,
            vulnerability_id=vulnerability.id,
            workflow_id=workflow_id,
            status=status,
            patch_applied=patch_applied,
            syntax_check_passed=syntax_passed,
            tests_passed=tests_passed,
            tests_run=tests_run_count,
            test_exit_code=test_result.exit_code if test_result else None,
            test_stdout=test_result.stdout if test_result else None,
            test_stderr=test_result.stderr if test_result else None,
            security_scan_passed=sec_scan_passed,
            original_vulnerability_resolved=orig_resolved,
            new_findings_count=len(new_findings_list),
            new_findings=new_findings_list,
            regression_detected=regression,
            failure_reason=failure_reason,
            failure_category=computed_category,
            validation_logs=validation_logs,
            sandbox_type=sandbox_type,
            duration=round(duration, 3),
            started_at=started_at,
            completed_at=completed_at,
            scanner_metadata=scanner_metadata or {},
        )

        # Status transitions
        patch_status = (
            PatchStatus.READY_FOR_REVIEW.value
            if status == ValidationStatus.PASSED
            else PatchStatus.FAILED_VALIDATION.value
        )
        # Update vulnerability and workflow status if passed
        def _update_entities(session):
            query = session.query(PatchAttemptModel).filter(PatchAttemptModel.id == patch_id)
            changed = query.filter(PatchAttemptModel.status.notin_(["APPROVED", "REJECTED"])).update(
                {PatchAttemptModel.status: patch_status, PatchAttemptModel.validation_id: result.id},
                synchronize_session="fetch")
            if not changed and query.first() is not None:
                raise PatchLifecycleConflict("Review was recorded; validation cannot replace reviewed evidence.")
            if status == ValidationStatus.PASSED:
                v = session.query(VulnerabilityModel).filter(VulnerabilityModel.id == vulnerability.id).first()
                if v:
                    v.status = "VALIDATED"

            if workflow_id:
                wf = session.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
                if wf and wf.status != "FAILED":
                    wf.current_stage = "VALIDATION_COMPLETE"

            if persist:
                model_rec = ValidationResultModel(
                    id=result.id,
                    patch_attempt_id=result.patch_attempt_id,
                    status=result.status.value,
                    patch_applied=result.patch_applied,
                    syntax_check_passed=result.syntax_check_passed,
                    tests_passed=result.tests_passed,
                    tests_run=result.tests_run,
                    test_exit_code=result.test_exit_code,
                    test_stdout=result.test_stdout,
                    test_stderr=result.test_stderr,
                    security_scan_passed=result.security_scan_passed,
                    original_vulnerability_resolved=result.original_vulnerability_resolved,
                    new_findings_count=result.new_findings_count,
                    new_findings=json.dumps(result.new_findings) if result.new_findings else None,
                    regression_detected=result.regression_detected,
                    failure_reason=result.failure_reason,
                    failure_category=result.failure_category,
                    validation_logs=result.validation_logs,
                    sandbox_type=result.sandbox_type,
                    duration=result.duration,
                    started_at=result.started_at,
                    completed_at=result.completed_at,
                    scanner_metadata=json.dumps(result.scanner_metadata),
                )
                session.add(model_rec)

        if not persist:
            return result
        if db_session is not None:
            _update_entities(db_session)
            db_session.commit()
        else:
            with session_scope() as session:
                _update_entities(session)

        # Audit event emission
        if persist:
            try:
                if status == ValidationStatus.PASSED:
                    meta = {
                        "sandbox_type": result.sandbox_type,
                        "syntax_check_passed": result.syntax_check_passed,
                        "tests_passed": result.tests_passed,
                        "tests_run": result.tests_run,
                        "security_scan_passed": result.security_scan_passed,
                        "original_vulnerability_resolved": result.original_vulnerability_resolved,
                        "new_findings_count": result.new_findings_count,
                        "duration": result.duration,
                    }
                    self.audit_service.record_event(
                        event_type=AuditEventType.PATCH_VALIDATED,
                        workflow_id=workflow_id,
                        vulnerability_id=vulnerability.id,
                        patch_attempt_id=patch_id,
                        validation_id=val_id,
                        event_status=AuditEventStatus.SUCCESS,
                        message=f"Patch {patch_id} passed isolated validation verification.",
                        metadata=meta,
                        session=db_session,
                    )
                    # HARD BOUNDARY: Record READY_FOR_REVIEW (No automatic merge/approval)
                    self.audit_service.record_event(
                        event_type=AuditEventType.READY_FOR_REVIEW,
                        workflow_id=workflow_id,
                        vulnerability_id=vulnerability.id,
                        patch_attempt_id=patch_id,
                        validation_id=val_id,
                        event_status=AuditEventStatus.SUCCESS,
                        message=f"Patch {patch_id} for vulnerability {vulnerability.id} is validated and READY_FOR_REVIEW.",
                        metadata={
                            "vulnerability_id": vulnerability.id,
                            "patch_attempt_id": patch_id,
                            "validation_id": val_id,
                            "action_required": "DEVELOPER_REVIEW",
                        },
                        session=db_session,
                    )
                else:
                    meta = {
                        "sandbox_type": result.sandbox_type,
                        "syntax_check_passed": result.syntax_check_passed,
                        "tests_passed": result.tests_passed,
                        "tests_run": result.tests_run,
                        "security_scan_passed": result.security_scan_passed,
                        "original_vulnerability_resolved": result.original_vulnerability_resolved,
                        "new_findings_count": result.new_findings_count,
                        "failure_category": result.failure_category,
                        "failure_reason": result.failure_reason,
                        "duration": result.duration,
                    }
                    self.audit_service.record_event(
                        event_type=AuditEventType.PATCH_VALIDATION_FAILED,
                        workflow_id=workflow_id,
                        vulnerability_id=vulnerability.id,
                        patch_attempt_id=patch_id,
                        validation_id=val_id,
                        event_status=AuditEventStatus.FAILED,
                        message=f"Patch {patch_id} validation failed: {result.failure_reason}",
                        metadata=meta,
                        session=db_session,
                    )
            except Exception as audit_err:
                logger.warning("Failed to record validation audit event: %s", audit_err)

        logger.info(
            "Validation run %s complete for patch %s in %.3fs (Verdict: %s)",
            val_id,
            patch_id,
            result.duration,
            result.status.value,
        )

        return result
