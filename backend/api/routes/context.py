"""FastAPI route for retrieving bounded repository context for vulnerability findings."""

import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import VulnerabilityModel, WorkflowModel
from backend.models.repository_context import RepositoryContext
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
)
from backend.services.repository_context import RepositoryContextService

router = APIRouter(prefix="/api", tags=["Repository Context"])


@router.get(
    "/vulnerabilities/{vulnerability_id}/context",
    response_model=RepositoryContext,
    status_code=status.HTTP_200_OK,
    summary="Get repository context for a vulnerability finding",
    description="Extracts bounded surrounding lines, Python AST enclosing scopes, imports, and related test files for a specific finding."
)
def get_vulnerability_context(
    vulnerability_id: str,
    db: Session = Depends(get_db)
) -> RepositoryContext:
    """Retrieve structured repository context for a specific vulnerability finding."""
    # 1. Locate vulnerability record
    vuln = db.query(VulnerabilityModel).filter(
        VulnerabilityModel.id == vulnerability_id
    ).first()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{vulnerability_id}' not found."
        )

    # 2. Locate associated workflow to identify target repository root
    wf = db.query(WorkflowModel).filter(
        WorkflowModel.id == vuln.workflow_id
    ).first()

    if not wf:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow '{vuln.workflow_id}' for vulnerability '{vulnerability_id}' not found."
        )

    # 3. Construct domain VulnerabilityFinding model
    raw_dict = json.loads(vuln.raw_finding) if vuln.raw_finding else None
    finding = VulnerabilityFinding(
        id=vuln.id,
        workflow_id=vuln.workflow_id,
        tool=vuln.tool,
        rule_id=vuln.rule_id,
        type=vuln.type,
        cwe=vuln.cwe,
        severity=Severity(vuln.severity) if vuln.severity in Severity.__members__ else Severity.MEDIUM,
        confidence=Confidence(vuln.confidence) if vuln.confidence and vuln.confidence in Confidence.__members__ else None,
        file_path=vuln.file_path,
        line_start=vuln.line_start,
        line_end=vuln.line_end,
        code_snippet=vuln.code_snippet,
        description=vuln.description,
        raw_finding=raw_dict,
        exploitability=vuln.exploitability,
        business_impact=vuln.business_impact,
        risk_score=vuln.risk_score,
        priority=vuln.priority,
        risk_reasoning=vuln.risk_reasoning,
        status=VulnerabilityStatus(vuln.status) if vuln.status in VulnerabilityStatus.__members__ else VulnerabilityStatus.DETECTED,
        created_at=vuln.created_at,
    )

    # 4. Extract repository context safely
    context_service = RepositoryContextService()
    try:
        context = context_service.build_context(
            repository_root=wf.repository_path,
            finding=finding,
        )
        return context
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to extract repository context: {str(e)}"
        )
