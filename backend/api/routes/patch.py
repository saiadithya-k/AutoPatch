"""FastAPI routes for automated patch generation and patch attempt history."""

import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.database.database import get_db
from backend.database.models import (
    PatchAttemptModel,
    RiskAssessmentModel,
    VulnerabilityModel,
    WorkflowModel,
)
from backend.models.patch import (
    PatchAttemptResponse,
    PatchGenerationRequest,
    PatchGenerationResult,
    PatchStatus,
)

router = APIRouter(prefix="/api", tags=["Patch Generation"])


@router.post(
    "/vulnerabilities/{vulnerability_id}/generate-patch",
    response_model=PatchGenerationResult,
    status_code=status.HTTP_200_OK,
    summary="Generate candidate security patch for a vulnerability",
    description="Invokes the Patch-Generation Agent to synthesize a minimal, targeted unified diff patch using repository context and LLM services without mutating original source."
)
def generate_patch_endpoint(
    vulnerability_id: str,
    request: Optional[PatchGenerationRequest] = None,
    db: Session = Depends(get_db)
) -> PatchGenerationResult:
    """Generate candidate patch for a prioritized vulnerability finding."""
    # 1. Check vulnerability exists
    vuln = db.query(VulnerabilityModel).filter(
        VulnerabilityModel.id == vulnerability_id
    ).first()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{vulnerability_id}' not found."
        )

    # 2. Check risk assessment exists
    ra = db.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.vulnerability_id == vulnerability_id
    ).first()

    if not ra and vuln.status not in ("ASSESSED", "PRIORITIZED"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Vulnerability '{vulnerability_id}' has not completed risk assessment. Run /assess-risk first."
        )

    attempt_number = request.attempt_number if request and request.attempt_number else 1
    feedback = request.feedback if request else None

    agent = PatchGenerationAgent()
    try:
        result = agent.generate_patch_for_vulnerability_id(
            vulnerability_id=vulnerability_id,
            attempt_number=attempt_number,
            feedback=feedback,
            persist=True,
            db_session=db,
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Patch generation error: {str(e)}"
        )


@router.get(
    "/vulnerabilities/{vulnerability_id}/patches",
    response_model=list[PatchAttemptResponse],
    summary="List patch attempts for a vulnerability",
    description="Retrieve chronological history of candidate patch attempts generated for a finding."
)
def get_vulnerability_patches(
    vulnerability_id: str,
    db: Session = Depends(get_db)
) -> list[PatchAttemptResponse]:
    """Retrieve all patch attempts for a specific vulnerability finding."""
    # Verify vulnerability exists
    vuln = db.query(VulnerabilityModel).filter(
        VulnerabilityModel.id == vulnerability_id
    ).first()

    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{vulnerability_id}' not found."
        )

    records = db.query(PatchAttemptModel).filter(
        PatchAttemptModel.vulnerability_id == vulnerability_id
    ).order_by(PatchAttemptModel.attempt_number.asc()).all()

    return [
        PatchAttemptResponse(
            id=r.id,
            workflow_id=r.workflow_id,
            vulnerability_id=r.vulnerability_id,
            attempt_number=r.attempt_number,
            patch_format=r.patch_format,
            patch_content=r.patch_content,
            explanation=r.explanation,
            files_changed=r.get_files_changed(),
            generation_model=r.generation_model,
            status=PatchStatus(r.status) if r.status in PatchStatus.__members__ else PatchStatus.GENERATED,
            created_at=r.created_at,
        )
        for r in records
    ]


@router.get(
    "/patches/{patch_id}",
    response_model=PatchAttemptResponse,
    summary="Get patch attempt by ID",
    description="Retrieve single patch attempt record with unified diff and explanation."
)
def get_patch_by_id(
    patch_id: str,
    db: Session = Depends(get_db)
) -> PatchAttemptResponse:
    """Retrieve single patch attempt record by patch ID."""
    record = db.query(PatchAttemptModel).filter(
        PatchAttemptModel.id == patch_id
    ).first()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch attempt '{patch_id}' not found."
        )

    return PatchAttemptResponse(
        id=record.id,
        workflow_id=record.workflow_id,
        vulnerability_id=record.vulnerability_id,
        attempt_number=record.attempt_number,
        patch_format=record.patch_format,
        patch_content=record.patch_content,
        explanation=record.explanation,
        files_changed=record.get_files_changed(),
        generation_model=record.generation_model,
        status=PatchStatus(record.status) if record.status in PatchStatus.__members__ else PatchStatus.GENERATED,
        created_at=record.created_at,
    )
