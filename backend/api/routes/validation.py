"""FastAPI routes for patch validation in isolated workspaces."""

import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.agents.validation_agent import ValidationAgent
from backend.database.database import get_db
from backend.database.models import PatchAttemptModel, ValidationResultModel
from backend.models.validation import ValidationResult, ValidationStatus

router = APIRouter(prefix="/api", tags=["Patch Validation"])


@router.post(
    "/patches/{patch_id}/validate",
    response_model=ValidationResult,
    status_code=status.HTTP_200_OK,
    summary="Validate candidate patch in an isolated temporary workspace",
    description="Applies candidate patch in an isolated temporary directory, executes tests and security re-scans, and produces a structured validation verdict."
)
def validate_patch_endpoint(
    patch_id: str,
    db: Session = Depends(get_db),
) -> ValidationResult:
    """Validate a candidate patch attempt in an isolated workspace."""
    patch_rec = db.query(PatchAttemptModel).filter(
        PatchAttemptModel.id == patch_id
    ).first()

    if not patch_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch attempt '{patch_id}' not found."
        )

    agent = ValidationAgent()
    try:
        result = agent.validate_patch(
            patch_id=patch_id,
            persist=True,
            db_session=db,
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation runtime failure: {str(e)}",
        )


@router.get(
    "/patches/{patch_id}/validation",
    response_model=ValidationResult,
    summary="Get latest validation result for a patch attempt",
    description="Retrieve the latest validation verdict and verification evidence for a specific patch attempt."
)
def get_patch_validation(
    patch_id: str,
    db: Session = Depends(get_db),
) -> ValidationResult:
    """Retrieve the latest validation result for a patch attempt."""
    patch_rec = db.query(PatchAttemptModel).filter(
        PatchAttemptModel.id == patch_id
    ).first()

    if not patch_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch attempt '{patch_id}' not found."
        )

    val_rec = db.query(ValidationResultModel).filter(
        ValidationResultModel.patch_attempt_id == patch_id
    ).order_by(ValidationResultModel.started_at.desc()).first()

    if not val_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No validation record found for patch attempt '{patch_id}'."
        )

    duration = val_rec.duration if val_rec.duration is not None and val_rec.duration > 0 else 0.0
    if duration == 0.0 and val_rec.completed_at and val_rec.started_at:
        duration = round((val_rec.completed_at - val_rec.started_at).total_seconds(), 3)

    new_findings_data = []
    if val_rec.new_findings:
        try:
            new_findings_data = json.loads(val_rec.new_findings)
        except Exception:
            new_findings_data = []

    return ValidationResult(
        id=val_rec.id,
        patch_attempt_id=val_rec.patch_attempt_id,
        vulnerability_id=patch_rec.vulnerability_id,
        workflow_id=patch_rec.workflow_id,
        status=ValidationStatus(val_rec.status) if val_rec.status in ValidationStatus.__members__ else ValidationStatus.FAILED,
        patch_applied=val_rec.patch_applied,
        syntax_check_passed=val_rec.syntax_check_passed if val_rec.syntax_check_passed is not None else False,
        tests_passed=val_rec.tests_passed,
        tests_run=val_rec.tests_run or 0,
        test_exit_code=val_rec.test_exit_code,
        test_stdout=val_rec.test_stdout,
        test_stderr=val_rec.test_stderr,
        security_scan_passed=val_rec.security_scan_passed,
        original_vulnerability_resolved=val_rec.original_vulnerability_resolved,
        new_findings_count=val_rec.new_findings_count if val_rec.new_findings_count is not None else len(new_findings_data),
        new_findings=new_findings_data,
        regression_detected=val_rec.regression_detected or False,
        failure_reason=val_rec.failure_reason,
        validation_logs=val_rec.validation_logs,
        sandbox_type=val_rec.sandbox_type or "local_workspace_dev_fallback",
        duration=duration,
        started_at=val_rec.started_at,
        completed_at=val_rec.completed_at,
    )


@router.get(
    "/validations/{validation_id}",
    response_model=ValidationResult,
    summary="Get validation record by ID",
    description="Retrieve a specific validation execution record and its diagnostics."
)
def get_validation_by_id(
    validation_id: str,
    db: Session = Depends(get_db),
) -> ValidationResult:
    """Retrieve validation record by validation ID."""
    val_rec = db.query(ValidationResultModel).filter(
        ValidationResultModel.id == validation_id
    ).first()

    if not val_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Validation record '{validation_id}' not found."
        )

    patch_rec = db.query(PatchAttemptModel).filter(
        PatchAttemptModel.id == val_rec.patch_attempt_id
    ).first()

    vuln_id = patch_rec.vulnerability_id if patch_rec else "unknown"
    wf_id = patch_rec.workflow_id if patch_rec else None

    duration = val_rec.duration if val_rec.duration is not None and val_rec.duration > 0 else 0.0
    if duration == 0.0 and val_rec.completed_at and val_rec.started_at:
        duration = round((val_rec.completed_at - val_rec.started_at).total_seconds(), 3)

    new_findings_data = []
    if val_rec.new_findings:
        try:
            new_findings_data = json.loads(val_rec.new_findings)
        except Exception:
            new_findings_data = []

    return ValidationResult(
        id=val_rec.id,
        patch_attempt_id=val_rec.patch_attempt_id,
        vulnerability_id=vuln_id,
        workflow_id=wf_id,
        status=ValidationStatus(val_rec.status) if val_rec.status in ValidationStatus.__members__ else ValidationStatus.FAILED,
        patch_applied=val_rec.patch_applied,
        syntax_check_passed=val_rec.syntax_check_passed if val_rec.syntax_check_passed is not None else False,
        tests_passed=val_rec.tests_passed,
        tests_run=val_rec.tests_run or 0,
        test_exit_code=val_rec.test_exit_code,
        test_stdout=val_rec.test_stdout,
        test_stderr=val_rec.test_stderr,
        security_scan_passed=val_rec.security_scan_passed,
        original_vulnerability_resolved=val_rec.original_vulnerability_resolved,
        new_findings_count=val_rec.new_findings_count if val_rec.new_findings_count is not None else len(new_findings_data),
        new_findings=new_findings_data,
        regression_detected=val_rec.regression_detected or False,
        failure_reason=val_rec.failure_reason,
        validation_logs=val_rec.validation_logs,
        sandbox_type=val_rec.sandbox_type or "local_workspace_dev_fallback",
        duration=duration,
        started_at=val_rec.started_at,
        completed_at=val_rec.completed_at,
    )
