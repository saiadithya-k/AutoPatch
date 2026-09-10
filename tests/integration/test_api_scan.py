"""Integration tests for FastAPI endpoints (/health, /api/scan, /api/vulnerabilities, /api/workflows)."""

from pathlib import Path
from fastapi.testclient import TestClient


def test_api_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "autopatch"
    assert data["version"] == "0.1.0"


def test_api_scan_vulnerable_project_success(client: TestClient, vulnerable_repo_path: Path):
    response = client.post(
        "/api/scan",
        json={"repository_path": str(vulnerable_repo_path)}
    )
    assert response.status_code == 200
    data = response.json()

    assert "workflow_id" in data
    assert data["status"] == "COMPLETED"
    assert data["findings_count"] >= 2
    assert len(data["findings"]) == data["findings_count"]

    workflow_id = data["workflow_id"]

    # Verify findings retrieval via /api/vulnerabilities
    vuln_resp = client.get(f"/api/vulnerabilities?workflow_id={workflow_id}")
    assert vuln_resp.status_code == 200
    vulns = vuln_resp.json()
    assert len(vulns) == data["findings_count"]

    # Verify workflow status retrieval via /api/workflows/{workflow_id}
    wf_resp = client.get(f"/api/workflows/{workflow_id}")
    assert wf_resp.status_code == 200
    wf_data = wf_resp.json()
    assert wf_data["id"] == workflow_id
    assert wf_data["status"] == "COMPLETED"


def test_api_scan_invalid_repository_path(client: TestClient):
    response = client.post(
        "/api/scan",
        json={"repository_path": "non_existent_path_directory_12345"}
    )
    assert response.status_code == 400
    data = response.json()
    assert "does not exist" in data["detail"]
