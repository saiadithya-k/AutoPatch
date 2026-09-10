"""Unit tests for Pydantic domain models and enums."""

from datetime import datetime
import pytest
from pydantic import ValidationError

from backend.models.vulnerability import (
    Confidence,
    HealthResponse,
    ScanRequest,
    ScanResponse,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
    WorkflowStatus,
)


def test_severity_enum():
    assert Severity.LOW == "LOW"
    assert Severity.MEDIUM == "MEDIUM"
    assert Severity.HIGH == "HIGH"
    assert Severity.CRITICAL == "CRITICAL"


def test_vulnerability_status_enum():
    assert VulnerabilityStatus.DETECTED == "DETECTED"
    assert VulnerabilityStatus.REMEDIATED == "REMEDIATED"
    assert VulnerabilityStatus.VALIDATED == "VALIDATED"
    assert VulnerabilityStatus.UNRESOLVED == "UNRESOLVED"


def test_workflow_status_enum():
    assert WorkflowStatus.CREATED == "CREATED"
    assert WorkflowStatus.SCANNING == "SCANNING"
    assert WorkflowStatus.COMPLETED == "COMPLETED"
    assert WorkflowStatus.FAILED == "FAILED"


def test_vulnerability_finding_instantiation():
    finding = VulnerabilityFinding(
        id="VULN-1234ABCD",
        tool="semgrep",
        rule_id="python.sql-injection",
        type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app/database.py",
        line_start=42,
        line_end=42,
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        description="SQL injection detected via string formatting",
        status=VulnerabilityStatus.DETECTED,
    )

    assert finding.id == "VULN-1234ABCD"
    assert finding.tool == "semgrep"
    assert finding.severity == Severity.HIGH
    assert finding.line_start == 42
    assert isinstance(finding.created_at, datetime)


def test_scan_request_validation():
    req = ScanRequest(repository_path="/valid/path", max_retries=5)
    assert req.repository_path == "/valid/path"
    assert req.max_retries == 5

    with pytest.raises(ValidationError):
        ScanRequest()  # repository_path is required


def test_scan_response_model():
    finding = VulnerabilityFinding(
        id="VULN-001",
        tool="bandit",
        type="Command Injection",
        severity=Severity.HIGH,
        file_path="app.py",
        description="os.system used",
    )
    resp = ScanResponse(
        workflow_id="wf-test-123",
        status=WorkflowStatus.COMPLETED,
        repository_path="/test/repo",
        findings_count=1,
        findings=[finding],
    )
    assert resp.workflow_id == "wf-test-123"
    assert resp.findings_count == 1
    assert len(resp.findings) == 1


def test_health_response():
    health = HealthResponse()
    assert health.status == "ok"
    assert health.service == "autopatch"
    assert health.version == "0.1.0"
