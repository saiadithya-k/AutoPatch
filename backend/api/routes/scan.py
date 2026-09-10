"""FastAPI routes for vulnerability scanning and findings retrieval."""

import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.agents.scanning_agent import ScanningAgent
from backend.database.database import get_db
from backend.database.models import VulnerabilityModel, WorkflowModel
from backend.models.vulnerability import (
    Confidence,
    ScanRequest,
    ScanResponse,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
    WorkflowResponse,
    WorkflowStatus,
)
from backend.services.repository import RepositoryValidationError

router = APIRouter(prefix="/api", tags=["Scanning"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger a static security scan on a repository",
    description="Executes Bandit and Semgrep against the supplied repository path, normalizes and deduplicates findings, and persists results to the database."
)
def run_scan(
    request: ScanRequest,
    db: Session = Depends(get_db)
) -> ScanResponse:
    """Execute repository scan synchronously and return normalized findings."""
    agent = ScanningAgent()

    try:
        findings, metadata = agent.scan(
            repository_path=request.repository_path,
            persist=True,
            db_session=db
        )
    except RepositoryValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scanning failed: {str(e)}"
        )

    workflow_id = metadata.get("workflow_id", "unknown")
    scan_status = metadata.get("scan_status", "COMPLETED")
    wf_status = WorkflowStatus.FAILED if scan_status == "FAILED" else WorkflowStatus.COMPLETED

    return ScanResponse(
        workflow_id=workflow_id,
        status=wf_status,
        repository_path=request.repository_path,
        findings_count=len(findings),
        findings=findings,
        scan_metadata=metadata
    )


@router.get(
    "/vulnerabilities",
    response_model=list[VulnerabilityFinding],
    summary="List detected vulnerabilities",
    description="Retrieve normalized vulnerabilities from database with optional filtering by workflow."
)
def get_vulnerabilities(
    workflow_id: Optional[str] = Query(None, description="Filter findings by workflow ID"),
    db: Session = Depends(get_db)
) -> list[VulnerabilityFinding]:
    """Retrieve persisted findings from database."""
    query = db.query(VulnerabilityModel)
    if workflow_id:
        query = query.filter(VulnerabilityModel.workflow_id == workflow_id)

    records = query.all()
    results = []
    for r in records:
        raw_dict = json.loads(r.raw_finding) if r.raw_finding else None
        results.append(
            VulnerabilityFinding(
                id=r.id,
                workflow_id=r.workflow_id,
                tool=r.tool,
                rule_id=r.rule_id,
                type=r.type,
                cwe=r.cwe,
                severity=Severity(r.severity) if r.severity in Severity.__members__ else Severity.MEDIUM,
                confidence=Confidence(r.confidence) if r.confidence and r.confidence in Confidence.__members__ else None,
                file_path=r.file_path,
                line_start=r.line_start,
                line_end=r.line_end,
                code_snippet=r.code_snippet,
                description=r.description,
                raw_finding=raw_dict,
                exploitability=r.exploitability,
                business_impact=r.business_impact,
                risk_score=r.risk_score,
                priority=r.priority,
                risk_reasoning=r.risk_reasoning,
                status=VulnerabilityStatus(r.status) if r.status in VulnerabilityStatus.__members__ else VulnerabilityStatus.DETECTED,
                created_at=r.created_at,
            )
        )
    return results


@router.get(
    "/workflows/{workflow_id}",
    response_model=WorkflowResponse,
    summary="Get workflow status",
    description="Retrieve status and execution details for a specific workflow run."
)
def get_workflow(
    workflow_id: str,
    db: Session = Depends(get_db)
) -> WorkflowResponse:
    """Retrieve workflow record by ID."""
    wf = db.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
    if not wf:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow '{workflow_id}' not found."
        )

    return WorkflowResponse(
        id=wf.id,
        repository_path=wf.repository_path,
        repository_url=wf.repository_url,
        branch=wf.branch,
        status=WorkflowStatus(wf.status) if wf.status in WorkflowStatus.__members__ else WorkflowStatus.FAILED,
        current_stage=wf.current_stage,
        max_retries=wf.max_retries,
        created_at=wf.created_at,
        started_at=wf.started_at,
        completed_at=wf.completed_at,
        error_message=wf.error_message
    )
