"""Integration tests for Patch Generation FastAPI endpoints:

POST /api/vulnerabilities/{vulnerability_id}/generate-patch
GET /api/vulnerabilities/{vulnerability_id}/patches
GET /api/patches/{patch_id}

Verifies success workflows, risk gating, 404 errors, and disk immutability.
"""

import hashlib
import os
from pathlib import Path
from fastapi.testclient import TestClient
import pytest


from backend.config import get_settings


def _compute_hashes(directory: Path) -> dict[str, str]:
    hashes = {}
    for root, _, files in os.walk(directory):
        for fname in files:
            p = Path(root) / fname
            if p.suffix in (".py", ".txt"):
                hashes[str(p.relative_to(directory))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return hashes


def test_api_patch_generation_and_retrieval(
    client: TestClient,
    vulnerable_repo_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    Test full API lifecycle:
    1. POST /api/scan
    2. POST /api/workflows/{id}/assess-risk
    3. POST /api/vulnerabilities/{vuln_id}/generate-patch
    4. GET /api/vulnerabilities/{vuln_id}/patches
    5. GET /api/patches/{patch_id}
    """
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    get_settings.cache_clear()
    initial_hashes = _compute_hashes(vulnerable_repo_path)

    # 1. Scan
    scan_resp = client.post(
        "/api/scan",
        json={"repository_path": str(vulnerable_repo_path)},
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    workflow_id = scan_data["workflow_id"]

    # 2. Risk assessment
    risk_resp = client.post(f"/api/workflows/{workflow_id}/assess-risk")
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    prioritized = risk_data["prioritized_vulnerabilities"]
    assert len(prioritized) > 0

    target_vuln_id = prioritized[0]["vulnerability"]["id"]

    # 3. Generate candidate patch
    patch_gen_resp = client.post(
        f"/api/vulnerabilities/{target_vuln_id}/generate-patch",
        json={"attempt_number": 1},
    )
    assert patch_gen_resp.status_code == 200
    patch_data = patch_gen_resp.json()

    assert patch_data["vulnerability_id"] == target_vuln_id
    assert patch_data["status"] == "GENERATED"
    assert patch_data["attempt_number"] == 1
    assert "unified_diff" in patch_data
    assert len(patch_data["unified_diff"]) > 0
    assert "--- a/" in patch_data["unified_diff"]
    patch_id = patch_data["id"]

    # 4. List patches for vulnerability
    list_patches_resp = client.get(f"/api/vulnerabilities/{target_vuln_id}/patches")
    assert list_patches_resp.status_code == 200
    patches_list = list_patches_resp.json()
    assert len(patches_list) >= 1
    assert patches_list[0]["id"] == patch_id
    assert patches_list[0]["status"] == "GENERATED"

    # 5. Get patch by ID
    get_patch_resp = client.get(f"/api/patches/{patch_id}")
    assert get_patch_resp.status_code == 200
    single_patch = get_patch_resp.json()
    assert single_patch["id"] == patch_id
    assert single_patch["vulnerability_id"] == target_vuln_id
    assert single_patch["patch_content"] == patch_data["unified_diff"]

    # 6. Verify repository files on disk remain strictly unmodified
    after_hashes = _compute_hashes(vulnerable_repo_path)
    assert initial_hashes == after_hashes


def test_api_patch_generation_missing_vulnerability(client: TestClient):
    """POST /api/vulnerabilities/{id}/generate-patch with non-existent ID returns 404."""
    resp = client.post("/api/vulnerabilities/non_existent_vuln_999/generate-patch")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_api_patch_retrieval_missing_ids(client: TestClient):
    """Test 404 behavior on non-existent patch and vulnerability endpoints."""
    resp1 = client.get("/api/vulnerabilities/non_existent_vuln_999/patches")
    assert resp1.status_code == 404

    resp2 = client.get("/api/patches/PATCH-NONEXISTENT")
    assert resp2.status_code == 404


def test_api_patch_generation_unassessed_risk_gating(client: TestClient, vulnerable_repo_path: Path):
    """Attempting patch generation on an unassessed vulnerability returns 400 Bad Request."""
    # 1. Scan repo to get detected findings
    scan_resp = client.post(
        "/api/scan",
        json={"repository_path": str(vulnerable_repo_path)},
    )
    assert scan_resp.status_code == 200
    workflow_id = scan_resp.json()["workflow_id"]

    # Get findings without running assess-risk
    vulns_resp = client.get(f"/api/vulnerabilities?workflow_id={workflow_id}")
    assert vulns_resp.status_code == 200
    vulns = vulns_resp.json()
    assert len(vulns) > 0
    raw_vuln_id = vulns[0]["id"]

    # 2. Try to generate patch before assessing risk
    resp = client.post(f"/api/vulnerabilities/{raw_vuln_id}/generate-patch")
    assert resp.status_code == 400
    assert "risk assessment" in resp.json()["detail"].lower()


def test_api_patch_generation_unconfigured_llm(
    client: TestClient,
    vulnerable_repo_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """When LLM provider is unconfigured, API returns a 200 with FAILED status and warning."""
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    get_settings.cache_clear()

    # Scan & assess
    scan_resp = client.post("/api/scan", json={"repository_path": str(vulnerable_repo_path)})
    wf_id = scan_resp.json()["workflow_id"]
    risk_resp = client.post(f"/api/workflows/{wf_id}/assess-risk")
    target_vuln_id = risk_resp.json()["prioritized_vulnerabilities"][0]["vulnerability"]["id"]

    # Patch generation with unconfigured LLM
    patch_resp = client.post(f"/api/vulnerabilities/{target_vuln_id}/generate-patch")
    assert patch_resp.status_code == 200
    data = patch_resp.json()
    assert data["status"] == "FAILED"
    assert any("llm_unconfigured" in w for w in data["warnings"])

