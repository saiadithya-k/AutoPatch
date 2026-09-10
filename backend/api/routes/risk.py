"""FastAPI routes for vulnerability risk assessment and prioritization."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.database.database import get_db
from backend.database.models import RiskAssessmentModel, VulnerabilityModel, WorkflowModel
from backend.models.risk_assessment import (
    AssessmentMethod,
    AssessRiskResponse,
    PriorityLevel,
    PrioritizedVulnerability,
    RiskAssessment,
)
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
    WorkflowStatus,
)

router = APIRouter(prefix="/api", tags=["Risk Assessment"])


@router.post(
    "/workflows/{workflow_id}/assess-risk",
    response_model=AssessRiskResponse,
    status_code=status.HTTP_200_OK,
    summary="Perform risk assessment and prioritization on workflow findings",
    description="Evaluates all detected vulnerabilities for a given workflow run, computes deterministic risk scores and priorities, and returns ranked findings."
)
def assess_workflow_risk(
    workflow_id: str,
    db: Session = Depends(get_db)
) -> AssessRiskResponse:
    """Assess and prioritize all vulnerabilities discovered in a workflow."""
    wf = db.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
    if not wf:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow '{workflow_id}' not found."
        )

    agent = RiskAssessmentAgent()
    try:
        prioritized = agent.assess_workflow(
            workflow_id=workflow_id,
            persist=True,
            db_session=db
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Risk assessment failed: {str(e)}"
        )

    return AssessRiskResponse(
        workflow_id=workflow_id,
        status=WorkflowStatus.RISK_ASSESSMENT,
        total_assessed=len(prioritized),
        prioritized_vulnerabilities=prioritized
    )


@router.get(
    "/vulnerabilities/{vulnerability_id}/risk",
    response_model=RiskAssessment,
    summary="Get risk assessment for a vulnerability",
    description="Retrieve the detailed risk assessment breakdown and reasoning for a specific vulnerability."
)
def get_vulnerability_risk(
    vulnerability_id: str,
    db: Session = Depends(get_db)
) -> RiskAssessment:
    """Retrieve risk assessment details for a specific vulnerability ID."""
    ra = db.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.vulnerability_id == vulnerability_id
    ).first()

    if not ra:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk assessment for vulnerability '{vulnerability_id}' not found."
        )

    return RiskAssessment(
        id=ra.id,
        vulnerability_id=ra.vulnerability_id,
        workflow_id=ra.workflow_id,
        severity=Severity(ra.severity) if ra.severity in Severity.__members__ else Severity.MEDIUM,
        severity_score=ra.severity_score,
        exploitability=ra.exploitability,
        business_impact=ra.business_impact,
        context_score=ra.context_score or 0.0,
        risk_score=ra.risk_score,
        priority=PriorityLevel(ra.priority) if ra.priority in PriorityLevel.__members__ else PriorityLevel.MEDIUM,
        reasoning=ra.reasoning,
        assessment_method=AssessmentMethod(ra.assessment_method) if ra.assessment_method in AssessmentMethod.__members__ else AssessmentMethod.DETERMINISTIC_RULES,
        model=ra.model,
        created_at=ra.created_at,
    )


@router.get(
    "/risk-assessments",
    response_model=list[RiskAssessment],
    summary="List all risk assessments",
    description="Retrieve risk assessment records with optional filtering by workflow ID or priority tier."
)
def list_risk_assessments(
    workflow_id: Optional[str] = Query(None, description="Filter by workflow run ID"),
    priority: Optional[PriorityLevel] = Query(None, description="Filter by priority tier"),
    db: Session = Depends(get_db)
) -> list[RiskAssessment]:
    """Retrieve filtered risk assessments from database."""
    query = db.query(RiskAssessmentModel)

    if workflow_id:
        query = query.filter(RiskAssessmentModel.workflow_id == workflow_id)
    if priority:
        query = query.filter(RiskAssessmentModel.priority == priority.value)

    records = query.order_by(RiskAssessmentModel.risk_score.desc()).all()

    return [
        RiskAssessment(
            id=r.id,
            vulnerability_id=r.vulnerability_id,
            workflow_id=r.workflow_id,
            severity=Severity(r.severity) if r.severity in Severity.__members__ else Severity.MEDIUM,
            severity_score=r.severity_score,
            exploitability=r.exploitability,
            business_impact=r.business_impact,
            context_score=r.context_score or 0.0,
            risk_score=r.risk_score,
            priority=PriorityLevel(r.priority) if r.priority in PriorityLevel.__members__ else PriorityLevel.MEDIUM,
            reasoning=r.reasoning,
            assessment_method=AssessmentMethod(r.assessment_method) if r.assessment_method in AssessmentMethod.__members__ else AssessmentMethod.DETERMINISTIC_RULES,
            model=r.model,
            created_at=r.created_at,
        )
        for r in records
    ]
