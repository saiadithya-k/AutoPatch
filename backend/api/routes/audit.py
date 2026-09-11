"""FastAPI routes for AutoPatch audit event inspection and timeline retrieval."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import AuditEventModel, WorkflowModel
from backend.models.audit import (
    AuditEventRecord,
    AuditEventStatus,
    AuditEventType,
)
from backend.services.audit import AuditService

router = APIRouter(prefix="/api", tags=["Audit & Lineage"])
audit_service = AuditService()


def _model_to_record(model: AuditEventModel) -> AuditEventRecord:
    """Helper to convert SQLAlchemy AuditEventModel to Pydantic AuditEventRecord."""
    return AuditEventRecord(
        id=model.id,
        workflow_id=model.workflow_id,
        vulnerability_id=model.vulnerability_id,
        patch_attempt_id=model.patch_attempt_id,
        validation_id=model.validation_id,
        event_type=AuditEventType(model.event_type) if model.event_type in AuditEventType.__members__ else model.event_type,
        event_status=AuditEventStatus(model.event_status) if model.event_status in AuditEventStatus.__members__ else model.event_status,
        message=model.message,
        metadata=model.get_metadata(),
        created_at=model.created_at,
    )


@router.get(
    "/audit/events",
    response_model=list[AuditEventRecord],
    status_code=status.HTTP_200_OK,
    summary="List lifecycle audit events with optional filtering",
    description="Retrieve filtered, sanitized audit events across scanning, assessment, patch generation, validation, and retries."
)
def list_audit_events_endpoint(
    workflow_id: Optional[str] = Query(None, description="Filter by workflow run ID"),
    vulnerability_id: Optional[str] = Query(None, description="Filter by vulnerability finding ID"),
    patch_attempt_id: Optional[str] = Query(None, description="Filter by candidate patch attempt ID"),
    validation_id: Optional[str] = Query(None, description="Filter by sandbox validation run ID"),
    event_type: Optional[str] = Query(None, description="Filter by AuditEventType name"),
    event_status: Optional[str] = Query(None, description="Filter by AuditEventStatus (SUCCESS, FAILED, WARNING, INFO)"),
    limit: int = Query(50, ge=1, le=500, description="Maximum records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> list[AuditEventRecord]:
    """List audit events with criteria-based filtering and pagination."""
    models = audit_service.list_events(
        session=db,
        workflow_id=workflow_id,
        vulnerability_id=vulnerability_id,
        patch_attempt_id=patch_attempt_id,
        validation_id=validation_id,
        event_type=event_type,
        event_status=event_status,
        limit=limit,
        offset=offset,
    )
    return [_model_to_record(m) for m in models]


@router.get(
    "/audit/events/{event_id}",
    response_model=AuditEventRecord,
    status_code=status.HTTP_200_OK,
    summary="Get single audit event by ID",
    description="Retrieve full details and sanitized metadata for a specific audit event."
)
def get_audit_event_endpoint(
    event_id: str,
    db: Session = Depends(get_db),
) -> AuditEventRecord:
    """Retrieve an audit event record by its unique ID."""
    model = audit_service.get_event(event_id=event_id, session=db)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit event '{event_id}' not found."
        )
    return _model_to_record(model)


@router.get(
    "/workflows/{workflow_id}/audit",
    response_model=list[AuditEventRecord],
    status_code=status.HTTP_200_OK,
    summary="Get workflow audit timeline in chronological order",
    description="Returns the complete chronological sequence of lifecycle events for an AutoPatch workflow."
)
def get_workflow_audit_timeline_endpoint(
    workflow_id: str,
    db: Session = Depends(get_db),
) -> list[AuditEventRecord]:
    """Retrieve all audit events for a workflow ordered chronologically by timestamp."""
    wf = db.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
    if not wf:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workflow '{workflow_id}' not found."
        )

    timeline_models = audit_service.get_workflow_timeline(workflow_id=workflow_id, session=db)
    return [_model_to_record(m) for m in timeline_models]
