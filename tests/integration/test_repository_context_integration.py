"""Integration tests for Repository Context Service and FastAPI context endpoint."""

from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.agents.scanning_agent import ScanningAgent
from backend.models.repository_context import RepositoryContext
from backend.services.repository_context import RepositoryContextService


def test_full_pipeline_to_repository_context(vulnerable_repo_path: Path, db_session: Session):
    """
    Test the complete AutoPatch pipeline up to Repository Context:
    vulnerable_project -> ScanningAgent -> RiskAssessmentAgent -> RepositoryContextService
    """
    # 1. Scan repository
    scanner = ScanningAgent()
    findings, metadata = scanner.scan(vulnerable_repo_path, persist=True, db_session=db_session)
    workflow_id = metadata["workflow_id"]
    assert len(findings) >= 2

    # 2. Risk assess workflow
    risk_agent = RiskAssessmentAgent()
    prioritized = risk_agent.assess_workflow(workflow_id, persist=True, db_session=db_session)
    assert len(prioritized) >= 2

    # 3. Target top vulnerability (Command Injection or Unsafe Eval in app.py)
    app_finding = next(p.vulnerability for p in prioritized if "app.py" in p.vulnerability.file_path)

    # 4. Extract repository context
    context_service = RepositoryContextService()
    ctx = context_service.build_context(
        repository_root=vulnerable_repo_path,
        finding=app_finding,
    )

    # 5. Verify extracted context properties
    assert isinstance(ctx, RepositoryContext)
    assert ctx.vulnerability_id == app_finding.id
    assert ctx.vulnerable_file == "app.py"
    assert ctx.language == "python"
    assert ctx.line_start == app_finding.line_start
    assert ctx.function_name in ("execute_system_diagnostic", "calculate_user_metric")
    assert ctx.enclosing_scope is not None
    assert ctx.enclosing_scope.scope_type == "function"
    assert len(ctx.surrounding_code) > 20
    assert len(ctx.imports) >= 2

    # Verify extracted imports
    imported_modules = [imp.module for imp in ctx.imports]
    assert "os" in imported_modules or "subprocess" in imported_modules or "typing" in imported_modules

    # Verify discovered related test file
    assert len(ctx.related_tests) >= 1
    rel_test = ctx.related_tests[0]
    assert "test_app.py" in rel_test.file_path
    assert "test_execute_system_diagnostic" in rel_test.test_names or "test_calculate_user_metric" in rel_test.test_names


def test_api_vulnerability_context_endpoint(client: TestClient, vulnerable_repo_path: Path):
    """
    Test GET /api/vulnerabilities/{vulnerability_id}/context end-to-end.
    """
    # 1. Trigger scan to populate database
    scan_resp = client.post("/api/scan", json={"repository_path": str(vulnerable_repo_path)})
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    workflow_id = scan_data["workflow_id"]
    findings = scan_data["findings"]
    assert len(findings) >= 1

    first_vuln_id = findings[0]["id"]

    # 2. Query context endpoint for valid finding
    ctx_resp = client.get(f"/api/vulnerabilities/{first_vuln_id}/context")
    assert ctx_resp.status_code == 200
    ctx_data = ctx_resp.json()

    assert ctx_data["vulnerability_id"] == first_vuln_id
    assert ctx_data["language"] == "python"
    assert len(ctx_data["surrounding_code"]) > 0
    assert ctx_data["context_window_start"] >= 1
    assert ctx_data["total_file_lines"] > 0

    # 3. Query context for non-existent vulnerability
    bad_resp = client.get("/api/vulnerabilities/non_existent_vuln_9999/context")
    assert bad_resp.status_code == 404
