"""AutoPatch Scanning Agent.

Coordinates repository validation, Bandit and Semgrep SAST executions,
finding normalization, cross-tool deduplication, and database persistence.
"""

import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def utc_now() -> datetime:
    """Return timezone-naive UTC datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from backend.database.database import session_scope
from backend.database.models import VulnerabilityModel, WorkflowModel
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
    WorkflowStatus,
)
from backend.models.audit import AuditEventStatus, AuditEventType
from backend.services.audit import AuditService
from backend.services.repository import RepositoryService, RepositoryValidationError
from backend.tools.bandit_runner import BanditResult, BanditRunner
from backend.tools.semgrep_runner import SemgrepResult, SemgrepRunner
from backend.tools.sandbox import get_default_sandbox_executor

logger = logging.getLogger(__name__)


class ScanningAgent:
    """Specialized Agent responsible for running static security analysis on Python repositories."""

    def __init__(
        self,
        bandit_runner: Optional[BanditRunner] = None,
        semgrep_runner: Optional[SemgrepRunner] = None,
        repository_service: Optional[RepositoryService] = None,
        audit_service: Optional[AuditService] = None,
    ):
        sandbox = get_default_sandbox_executor() if bandit_runner is None or semgrep_runner is None else None
        self.bandit_runner = bandit_runner or BanditRunner(sandbox=sandbox)
        self.semgrep_runner = semgrep_runner or SemgrepRunner(sandbox=sandbox)
        self.repository_service = repository_service or RepositoryService()
        self.audit_service = audit_service or AuditService()

    def _normalize_path(self, file_path_str: str, repo_root: Path) -> str:
        """
        Normalize a file path to a relative POSIX-style path from repo_root.
        """
        try:
            p = Path(file_path_str)
            if not p.is_absolute():
                p = repo_root / p
            p = p.resolve()
            rel = p.relative_to(repo_root.resolve())
            return rel.as_posix()
        except Exception:
            # Fallback to posix clean path
            return Path(file_path_str).as_posix()

    def _generate_finding_id(
        self,
        tool: str,
        file_path: str,
        line_start: Optional[int],
        rule_id: Optional[str],
        workflow_id: Optional[str] = None
    ) -> str:
        """
        Generate a deterministic finding identifier.
        Incorporates workflow_id if provided to maintain uniqueness across workflow records in DB.
        """
        raw_key = f"{workflow_id or 'global'}:{file_path}:{line_start or 0}:{rule_id or 'unknown'}"
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:8].upper()
        return f"VULN-{digest}"

    def _normalize_bandit_finding(self, finding: dict[str, Any], repo_root: Path, workflow_id: Optional[str]) -> VulnerabilityFinding:
        """Convert a raw Bandit finding into a normalized VulnerabilityFinding."""
        rule_id = finding.get("test_id", "")
        test_name = finding.get("test_name", "")
        issue_text = finding.get("issue_text", "Security issue detected by Bandit")
        raw_filename = finding.get("filename", "")
        file_path = self._normalize_path(raw_filename, repo_root)
        line_start = finding.get("line_number")
        line_range = finding.get("line_range", [])
        line_end = line_range[-1] if line_range else line_start
        code_snippet = finding.get("code", "").strip()

        # Map Bandit severity (LOW, MEDIUM, HIGH)
        raw_sev = (finding.get("issue_severity") or "MEDIUM").upper()
        severity_map = {
            "LOW": Severity.LOW,
            "MEDIUM": Severity.MEDIUM,
            "HIGH": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL,
        }
        severity = severity_map.get(raw_sev, Severity.MEDIUM)

        # Map Bandit confidence
        raw_conf = (finding.get("issue_confidence") or "MEDIUM").upper()
        conf_map = {
            "LOW": Confidence.LOW,
            "MEDIUM": Confidence.MEDIUM,
            "HIGH": Confidence.HIGH,
            "UNDEFINED": Confidence.UNDEFINED,
        }
        confidence = conf_map.get(raw_conf, Confidence.MEDIUM)

        # CWE Extraction
        cwe_dict = finding.get("issue_cwe", {})
        cwe_id = None
        if isinstance(cwe_dict, dict) and "id" in cwe_dict:
            cwe_id = f"CWE-{cwe_dict['id']}"
        elif isinstance(cwe_dict, str):
            cwe_id = cwe_dict

        # Human-readable title
        vuln_type = test_name.replace("_", " ").title() if test_name else (cwe_id or "Python SAST Issue")

        finding_id = self._generate_finding_id("bandit", file_path, line_start, rule_id, workflow_id)

        return VulnerabilityFinding(
            id=finding_id,
            workflow_id=workflow_id,
            tool="bandit",
            rule_id=rule_id or None,
            type=vuln_type,
            cwe=cwe_id,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet or None,
            description=issue_text,
            raw_finding=finding,
            status=VulnerabilityStatus.DETECTED,
            created_at=utc_now(),
        )

    def _normalize_semgrep_finding(self, finding: dict[str, Any], repo_root: Path, workflow_id: Optional[str]) -> VulnerabilityFinding:
        """Convert a raw Semgrep finding into a normalized VulnerabilityFinding."""
        rule_id = finding.get("check_id", "")
        raw_path = finding.get("path", "")
        file_path = self._normalize_path(raw_path, repo_root)
        start_pos = finding.get("start", {})
        end_pos = finding.get("end", {})
        line_start = start_pos.get("line")
        line_end = end_pos.get("line") or line_start

        extra = finding.get("extra", {})
        description = extra.get("message", "Security issue detected by Semgrep")
        code_snippet = extra.get("lines", "").strip()

        # Map Semgrep severity: INFO, WARNING, ERROR, CRITICAL
        raw_sev = (extra.get("severity") or "WARNING").upper()
        severity_map = {
            "INFO": Severity.LOW,
            "LOW": Severity.LOW,
            "WARNING": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "ERROR": Severity.HIGH,
            "HIGH": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL,
        }
        severity = severity_map.get(raw_sev, Severity.MEDIUM)

        # Metadata extraction
        metadata = extra.get("metadata", {})
        cwe_raw = metadata.get("cwe")
        cwe_id = None
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe_id = str(cwe_raw[0])
        elif isinstance(cwe_raw, str):
            cwe_id = cwe_raw
        if cwe_id:
            match = re.search(r"CWE-\d+", cwe_id)
            cwe_id = match.group(0) if match else cwe_id

        raw_conf = (metadata.get("confidence") or "MEDIUM").upper()
        conf_map = {
            "LOW": Confidence.LOW,
            "MEDIUM": Confidence.MEDIUM,
            "HIGH": Confidence.HIGH,
            "UNDEFINED": Confidence.UNDEFINED,
        }
        confidence = conf_map.get(raw_conf, Confidence.MEDIUM)

        # Derive human readable type
        category = metadata.get("category", "")
        if category:
            vuln_type = category.replace("-", " ").title()
        elif rule_id:
            vuln_type = rule_id.split(".")[-1].replace("-", " ").title()
        else:
            vuln_type = cwe_id or "Semgrep Security Finding"

        finding_id = self._generate_finding_id("semgrep", file_path, line_start, rule_id, workflow_id)

        return VulnerabilityFinding(
            id=finding_id,
            workflow_id=workflow_id,
            tool="semgrep",
            rule_id=rule_id or None,
            type=vuln_type,
            cwe=cwe_id,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet or None,
            description=description,
            raw_finding=finding,
            status=VulnerabilityStatus.DETECTED,
            created_at=utc_now(),
        )

    def _deduplicate_findings(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        """
        Deduplicate findings when Bandit and Semgrep report the same underlying vulnerability.

        Matching criteria:
        - Same relative file_path
        - Overlapping line range (within 2 lines)
        - Either identical finding ID, identical rule/CWE, or related vulnerability classification.
        """
        deduped: list[VulnerabilityFinding] = []

        def identity(finding):
            return {name: getattr(finding, name) for name in
                    ("tool", "rule_id", "cwe", "type", "file_path", "line_start", "line_end")}

        for finding in findings:
            raw = dict(finding.raw_finding or {})
            raw.setdefault("_autopatch_provenance", [identity(finding)])
            finding.raw_finding = raw
            matched = False
            for existing in deduped:
                # Same file check
                if existing.file_path != finding.file_path:
                    continue

                # Line proximity check
                lines_overlap = False
                if existing.line_start is not None and finding.line_start is not None:
                    lines_overlap = abs(existing.line_start - finding.line_start) <= 2
                elif existing.line_start == finding.line_start:
                    lines_overlap = True

                if lines_overlap:
                    # Check semantic match
                    same_id = existing.id == finding.id
                    same_cwe = existing.cwe and finding.cwe and (existing.cwe == finding.cwe)
                    same_type = (
                        existing.type.lower() in finding.type.lower()
                        or finding.type.lower() in existing.type.lower()
                    )

                    if same_id or (existing.tool != finding.tool and (same_cwe or same_type)):
                        # Merge provenance into existing finding
                        existing.raw_finding["_autopatch_provenance"].extend(raw["_autopatch_provenance"])
                        if finding.tool not in existing.tool:
                            existing.tool = f"{existing.tool}, {finding.tool}"
                        # Prefer higher severity if difference exists
                        sev_order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
                        if sev_order.get(finding.severity, 0) > sev_order.get(existing.severity, 0):
                            existing.severity = finding.severity
                        if not existing.cwe and finding.cwe:
                            existing.cwe = finding.cwe
                        if not existing.code_snippet and finding.code_snippet:
                            existing.code_snippet = finding.code_snippet
                        matched = True
                        break

            if not matched:
                deduped.append(finding)

        return deduped

    def scan(
        self,
        repository_path: str | Path,
        workflow_id: Optional[str] = None,
        persist: bool = True,
        db_session: Optional[Any] = None,
        manage_workflow: bool = True,
    ) -> tuple[list[VulnerabilityFinding], dict[str, Any]]:
        """
        Perform a comprehensive static vulnerability scan on a Python repository.

        Steps:
        1. Validate repository path exists and is a directory.
        2. Run Bandit scanner.
        3. Run Semgrep scanner.
        4. Normalize findings from both tools.
        5. Deduplicate overlapping findings.
        6. Persist results to SQLite database if persist=True.
        7. Return list of normalized findings and execution metadata.

        :param repository_path: Filesystem path to target repository.
        :param workflow_id: Optional workflow ID. If None, generated automatically.
        :param persist: Whether to save findings and workflow to the database.
        :param db_session: Optional active SQLAlchemy session for persistence.
        :return: Tuple of (list of VulnerabilityFinding, metadata dict).
        """
        start_time = time.time()
        workflow_id = workflow_id or f"wf-{uuid.uuid4().hex[:8]}"

        # 1. Validate repository path
        try:
            validated_path = self.repository_service.validate_repository_path(str(repository_path))
        except RepositoryValidationError as e:
            logger.error("Repository validation failed: %s", e)
            if persist and manage_workflow:
                self._record_failed_workflow(workflow_id, str(repository_path), str(e), db_session=db_session)
            raise

        logger.info("Starting scan for workflow %s at %s", workflow_id, validated_path)

        # 2. Record initial workflow state in database
        if persist:
            if manage_workflow:
                self._record_started_workflow(workflow_id, str(validated_path), db_session=db_session)
            self.audit_service.record_event(
                event_type=AuditEventType.SCAN_STARTED,
                workflow_id=workflow_id,
                event_status=AuditEventStatus.INFO,
                message=f"Static security scan initiated for repository '{validated_path}'.",
                metadata={"repository_path": str(validated_path)},
                session=db_session,
            )

        all_findings: list[VulnerabilityFinding] = []
        scanner_metadata: dict[str, Any] = {
            "workflow_id": workflow_id,
            "repository_path": str(validated_path),
            "bandit": {},
            "semgrep": {},
            "errors": [],
        }

        # 3. Execute Bandit
        bandit_result: Optional[BanditResult] = None
        try:
            bandit_result = self.bandit_runner.run(validated_path)
            scanner_metadata["bandit"] = {
                "success": bandit_result.success,
                "exit_code": bandit_result.exit_code,
                "raw_findings_count": len(bandit_result.findings),
                "error_message": bandit_result.error_message,
                "errors": bandit_result.errors,
                "ruleset": "bandit-default",
            }
            if bandit_result.success:
                for raw in bandit_result.findings:
                    all_findings.append(
                        self._normalize_bandit_finding(raw, validated_path, workflow_id)
                    )
            else:
                msg = f"Bandit execution warning: {bandit_result.error_message}"
                logger.warning(msg)
                scanner_metadata["errors"].append(msg)
        except Exception as e:
            logger.error("Unexpected error running Bandit: %s", e)
            scanner_metadata["bandit"] = {"success": False, "error": str(e)}
            scanner_metadata["errors"].append(f"Bandit crashed: {e}")

        # 4. Execute Semgrep
        semgrep_result: Optional[SemgrepResult] = None
        try:
            semgrep_result = self.semgrep_runner.run(validated_path)
            scanner_metadata["semgrep"] = {
                "success": semgrep_result.success,
                "exit_code": semgrep_result.exit_code,
                "raw_findings_count": len(semgrep_result.findings),
                "error_message": semgrep_result.error_message,
                "errors": semgrep_result.errors,
                "ruleset": getattr(self.semgrep_runner, "ruleset_provenance", None),
            }
            if semgrep_result.success:
                for raw in semgrep_result.findings:
                    all_findings.append(
                        self._normalize_semgrep_finding(raw, validated_path, workflow_id)
                    )
            else:
                msg = f"Semgrep execution warning: {semgrep_result.error_message}"
                logger.warning(msg)
                scanner_metadata["errors"].append(msg)
        except Exception as e:
            logger.error("Unexpected error running Semgrep: %s", e)
            scanner_metadata["semgrep"] = {"success": False, "error": str(e)}
            scanner_metadata["errors"].append(f"Semgrep crashed: {e}")

        # 5. Deduplicate findings across tools
        normalized_findings = self._deduplicate_findings(all_findings)

        # 6. Determine overall scan status
        bandit_ok = bool(bandit_result and bandit_result.success and not bandit_result.errors)
        semgrep_ok = bool(semgrep_result and semgrep_result.success and not semgrep_result.errors)
        scanner_metadata["coverage_complete"] = bandit_ok and semgrep_ok
        scanner_metadata["required_scanners"] = ["bandit", "semgrep"]

        if bandit_ok and semgrep_ok:
            scan_status = "COMPLETED"
            workflow_status = WorkflowStatus.COMPLETED
            current_stage = "SCAN_COMPLETE"
        elif bandit_ok or semgrep_ok:
            scan_status = "DEGRADED"
            workflow_status = WorkflowStatus.COMPLETED
            current_stage = "SCAN_COMPLETE_DEGRADED"
        else:
            scan_status = "FAILED"
            workflow_status = WorkflowStatus.FAILED
            current_stage = "SCAN_FAILED"

        elapsed = time.time() - start_time
        scanner_metadata["scan_duration_seconds"] = round(elapsed, 2)
        scanner_metadata["total_normalized_findings"] = len(normalized_findings)
        scanner_metadata["scan_status"] = scan_status

        # 7. Persist to Database
        if persist:
            err_msg = "; ".join(scanner_metadata["errors"]) if scan_status == "FAILED" else None
            self._persist_findings(
                workflow_id,
                normalized_findings,
                status=workflow_status,
                current_stage=current_stage,
                error_message=err_msg,
                db_session=db_session,
                manage_workflow=manage_workflow,
            )
            if scan_status == "COMPLETED":
                ev_type = AuditEventType.SCAN_COMPLETED
                ev_status = AuditEventStatus.SUCCESS
            elif scan_status == "DEGRADED":
                ev_type = AuditEventType.SCAN_DEGRADED
                ev_status = AuditEventStatus.WARNING
            else:
                ev_type = AuditEventType.SCAN_FAILED
                ev_status = AuditEventStatus.FAILED

            self.audit_service.record_event(
                event_type=ev_type,
                workflow_id=workflow_id,
                event_status=ev_status,
                message=f"Static security scan finished with status '{scan_status}'. Discovered {len(normalized_findings)} findings.",
                metadata={
                    "scanner_status": scan_status,
                    "finding_count": len(normalized_findings),
                    "duration": round(elapsed, 2),
                    "bandit_findings_count": len(bandit_result.findings) if bandit_result and bandit_result.findings else 0,
                    "semgrep_findings_count": len(semgrep_result.findings) if semgrep_result and semgrep_result.findings else 0,
                    "scanner_metadata": scanner_metadata,
                },
                session=db_session,
            )

        logger.info(
            "Scan %s for workflow %s: %d findings discovered in %.2fs (Status: %s)",
            scan_status.lower(),
            workflow_id,
            len(normalized_findings),
            elapsed,
            scan_status,
        )

        return normalized_findings, scanner_metadata

    def _execute_in_session(self, db_session: Optional[Any], fn) -> None:
        """Execute callback either in provided session or a new scoped session."""
        if db_session is not None:
            fn(db_session)
            db_session.commit()
        else:
            with session_scope() as session:
                fn(session)

    def _record_started_workflow(self, workflow_id: str, repo_path: str, db_session: Optional[Any] = None) -> None:
        """Create or update workflow record in DB with SCANNING state."""
        now = utc_now()

        def _do(session):
            wf = session.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
            if not wf:
                wf = WorkflowModel(
                    id=workflow_id,
                    repository_path=repo_path,
                    status=WorkflowStatus.SCANNING.value,
                    current_stage="SCANNING",
                    started_at=now,
                )
                session.add(wf)
            else:
                wf.status = WorkflowStatus.SCANNING.value
                wf.current_stage = "SCANNING"
                wf.started_at = now

        self._execute_in_session(db_session, _do)

    def _record_failed_workflow(self, workflow_id: str, repo_path: str, error_msg: str, db_session: Optional[Any] = None) -> None:
        """Record workflow failure in database."""
        now = utc_now()

        def _do(session):
            wf = session.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
            if not wf:
                wf = WorkflowModel(
                    id=workflow_id,
                    repository_path=repo_path,
                    status=WorkflowStatus.FAILED.value,
                    error_message=error_msg,
                    completed_at=now,
                )
                session.add(wf)
            else:
                wf.status = WorkflowStatus.FAILED.value
                wf.error_message = error_msg
                wf.completed_at = now

        self._execute_in_session(db_session, _do)
        try:
            self.audit_service.record_event(
                event_type=AuditEventType.SCAN_FAILED,
                workflow_id=workflow_id,
                event_status=AuditEventStatus.FAILED,
                message=f"Scan failed: {error_msg}",
                metadata={"repository_path": repo_path, "error": error_msg},
                session=db_session,
            )
        except Exception as audit_err:
            logger.warning("Failed to record SCAN_FAILED audit event: %s", audit_err)

    def _persist_findings(
        self,
        workflow_id: str,
        findings: list[VulnerabilityFinding],
        status: WorkflowStatus = WorkflowStatus.COMPLETED,
        current_stage: str = "SCAN_COMPLETE",
        error_message: Optional[str] = None,
        db_session: Optional[Any] = None,
        manage_workflow: bool = True,
    ) -> None:
        """Persist normalized vulnerability findings and workflow execution state to the database."""
        now = utc_now()

        def _do(session):
            wf = session.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
            if wf and manage_workflow:
                wf.status = status.value
                wf.current_stage = current_stage
                wf.completed_at = now
                if error_message:
                    wf.error_message = error_message

            # Clean previous findings for this workflow run if any
            session.query(VulnerabilityModel).filter(
                VulnerabilityModel.workflow_id == workflow_id
            ).delete()

            for f in findings:
                vuln_record = VulnerabilityModel(
                    id=f.id,
                    workflow_id=workflow_id,
                    tool=f.tool,
                    rule_id=f.rule_id,
                    type=f.type,
                    cwe=f.cwe,
                    severity=f.severity.value,
                    confidence=f.confidence.value if f.confidence else None,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    code_snippet=f.code_snippet,
                    description=f.description,
                    raw_finding=json.dumps(f.raw_finding) if f.raw_finding else None,
                    status=f.status.value,
                    created_at=f.created_at,
                    updated_at=now,
                )
                session.add(vuln_record)

        self._execute_in_session(db_session, _do)

    # Reusable alias for scan
    scan_repository = scan
