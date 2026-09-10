"""Integration tests for Phase 2 Risk-Assessment Agent and FastAPI endpoints."""

from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.agents.scanning_agent import ScanningAgent
from backend.models.risk_assessment import PriorityLevel
from backend.models.vulnerability import VulnerabilityStatus


def test_real_scan_to_risk_assessment_pipeline(vulnerable_repo_path: Path, db_session: Session):
    """
    Test the full pipeline:
    vulnerable_project -> ScanningAgent -> RiskAssessmentAgent -> SQLite -> Prioritized Findings
    """
    scanner = ScanningAgent()
    findings, metadata = scanner.scan(
        vulnerable_repo_path,
        persist=True,
        db_session=db_session
    )
    workflow_id = metadata["workflow_id"]
    assert len(findings) >= 3

    risk_agent = RiskAssessmentAgent()
    prioritized = risk_agent.assess_workflow(
        workflow_id=workflow_id,
        persist=True,
        db_session=db_session
    )

    assert len(prioritized) == len(findings)

    # Verify top findings are the actual critical vulnerabilities (Command injection & SQLi)
    top_vulns = prioritized[:3]
    top_types = [p.vulnerability.type.lower() for p in top_vulns]
    top_files = [p.vulnerability.file_path for p in top_vulns]

    # Command injection or SQL injection must be in top ranks
    assert any("start process" in t or "command" in t or "blacklist" in t or "sql" in t for t in top_types)
    assert "app.py" in top_files or "database.py" in top_files

    # Top finding must be HIGH or CRITICAL priority
    assert prioritized[0].risk_assessment.priority in (PriorityLevel.CRITICAL, PriorityLevel.HIGH)

    # Test file findings must be LOW priority
    test_file_findings = [p for p in prioritized if "test_app.py" in p.vulnerability.file_path]
    for tf in test_file_findings:
        assert tf.risk_assessment.priority == PriorityLevel.LOW
        assert tf.risk_assessment.risk_score < 4.0


def test_api_risk_assessment_endpoints_end_to_end(client: TestClient, vulnerable_repo_path: Path):
    """
    Test FastAPI endpoints:
    1. POST /api/scan
    2. POST /api/workflows/{workflow_id}/assess-risk
    3. GET /api/vulnerabilities/{vulnerability_id}/risk
    4. GET /api/risk-assessments
    """
    # 1. Trigger static scan
    scan_resp = client.post(
        "/api/scan",
        json={"repository_path": str(vulnerable_repo_path)}
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    workflow_id = scan_data["workflow_id"]
    findings_count = scan_data["findings_count"]
    assert findings_count >= 2

    # 2. Trigger risk assessment on workflow
    risk_resp = client.post(f"/api/workflows/{workflow_id}/assess-risk")
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()

    assert risk_data["workflow_id"] == workflow_id
    assert risk_data["status"] == "RISK_ASSESSMENT"
    assert risk_data["total_assessed"] == findings_count
    prioritized = risk_data["prioritized_vulnerabilities"]
    assert len(prioritized) == findings_count

    # Check rank order
    for idx, p in enumerate(prioritized, start=1):
        assert p["rank"] == idx
        assert 0.0 <= p["risk_assessment"]["risk_score"] <= 10.0
        assert p["risk_assessment"]["priority"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    first_vuln_id = prioritized[0]["vulnerability"]["id"]

    # 3. Retrieve single vulnerability risk assessment
    vuln_risk_resp = client.get(f"/api/vulnerabilities/{first_vuln_id}/risk")
    assert vuln_risk_resp.status_code == 200
    vuln_risk_data = vuln_risk_resp.json()
    assert vuln_risk_data["vulnerability_id"] == first_vuln_id
    assert vuln_risk_data["risk_score"] == prioritized[0]["risk_assessment"]["risk_score"]
    assert len(vuln_risk_data["reasoning"]) > 10

    # 4. List all risk assessments
    list_resp = client.get(f"/api/risk-assessments?workflow_id={workflow_id}")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert len(list_data) == findings_count

    # 5. Non-existent workflow should return 404
    bad_resp = client.post("/api/workflows/non_existent_wf_123/assess-risk")
    assert bad_resp.status_code == 404
