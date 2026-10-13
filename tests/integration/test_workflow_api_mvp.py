"""Public workflow/review/report contracts without external runtime services."""
from unittest.mock import patch
from backend.database.models import WorkflowModel, VulnerabilityModel, PatchAttemptModel, ValidationResultModel


def test_create_and_poll_workflow(client, vulnerable_repo_path):
    with patch("backend.api.routes.workflows.workflow_jobs.submit") as submit:
        response = client.post("/api/workflows", json={"repository_path": str(vulnerable_repo_path), "max_retries": 0})
    assert response.status_code == 202
    workflow_id = response.json()["id"]
    submit.assert_called_once_with(workflow_id)
    detail = client.get(f"/api/workflows/{workflow_id}")
    assert detail.status_code == 200
    assert detail.json()["max_retries"] == 0
    assert detail.json()["processed_findings"] == 0
    assert client.get("/api/workflows").json()["total"] == 1


def test_repository_containment(client, tmp_path, vulnerable_repo_path, monkeypatch):
    from backend.config import get_settings
    monkeypatch.setattr(get_settings(), "ALLOWED_REPOSITORY_ROOT", str(vulnerable_repo_path))
    response = client.post("/api/workflows", json={"repository_path": str(tmp_path)})
    assert response.status_code == 422
    assert "outside allowed" in response.json()["detail"]


def test_review_report_roundtrip(client, db_session, vulnerable_repo_path):
    from backend.database.models import utc_now
    wf = WorkflowModel(id="wf-review", repository_path=str(vulnerable_repo_path), status="READY_FOR_REVIEW", completed_at=utc_now(), reviewable_count=1, total_findings=1, processed_findings=1)
    finding = VulnerabilityModel(id="v-review", workflow_id=wf.id, tool="bandit", severity="HIGH", type="issue", description="issue", file_path="app.py")
    candidate = PatchAttemptModel(id="p-review", workflow_id=wf.id, vulnerability_id=finding.id, patch_content="diff", status="READY_FOR_REVIEW")
    evidence = ValidationResultModel(id="val-review", patch_attempt_id=candidate.id, status="PASSED", patch_applied=True, syntax_check_passed=True, tests_passed=True, security_scan_passed=True, original_vulnerability_resolved=True, scanner_metadata='{"coverage_complete": true}')
    db_session.add_all([wf, finding, candidate, evidence])
    db_session.commit()
    body = {"reviewer_label": "Local developer", "comment": "Looks correct"}
    response = client.post("/api/patches/p-review/approve", json=body)
    assert response.status_code == 200
    assert response.json()["validation_id"] == evidence.id
    assert client.post("/api/patches/p-review/approve", json=body).status_code == 200
    assert client.post("/api/patches/p-review/reject", json=body).status_code == 409
    assert client.get("/api/patches/p-review").json()["review"]["decision"] == "APPROVED"
    report = client.get("/api/reports/wf-review").json()
    assert report["validations"][0]["scanner_metadata"]["coverage_complete"] is True
    assert report["workflow"]["status"] == "APPROVED"
    assert report["workflow"]["reviewable_count"] == 0
    assert report["unresolved_findings"] == []
    assert client.get("/api/patches?workflow_id=wf-review").json()["total"] == 1


def test_unknown_resources(client):
    assert client.get("/api/workflows/missing").status_code == 404
    assert client.get("/api/vulnerabilities/missing").status_code == 404
    assert client.get("/api/reports/missing").status_code == 404
