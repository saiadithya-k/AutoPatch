"""Workflow creation, polling, persisted reports, and review decisions."""
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.config import get_settings
from backend.database.database import get_db
from backend.database.models import WorkflowModel, VulnerabilityModel, PatchAttemptModel
from backend.models.workflow import WorkflowCreate, WorkflowCreated, WorkflowDetail, ReviewRequest, ReviewResponse
from backend.services.repository import RepositoryValidationError
from backend.services.workflows import workflow_jobs, validate_repository
from backend.services.reports import workflow_data, workflow_report, patch_data, row_data
from backend.services.review import record_review

router = APIRouter(prefix="/api", tags=["Workflows and Review"])


@router.post("/workflows", response_model=WorkflowCreated, status_code=202)
def create_workflow(request: WorkflowCreate, db: Session = Depends(get_db)):
    try:
        path = validate_repository(request.repository_path)
    except RepositoryValidationError as error:
        raise HTTPException(422, str(error))
    wf = WorkflowModel(id=f"wf-{uuid.uuid4().hex}", repository_path=str(path), status="CREATED", current_stage="QUEUED", max_retries=request.max_retries if request.max_retries is not None else get_settings().MAX_PATCH_RETRIES, request_json=request.model_dump_json())
    db.add(wf)
    db.commit()
    try:
        workflow_jobs.submit(wf.id)
    except RuntimeError as error:
        wf.status = "FAILED"
        wf.outcome = "CAPACITY_REJECTED"
        wf.error_message = str(error)
        db.commit()
        raise HTTPException(503, str(error))
    return WorkflowCreated(id=wf.id, status="CREATED", detail_url=f"/api/workflows/{wf.id}")


@router.get("/workflows")
def list_workflows(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    query = db.query(WorkflowModel)
    return {"items": [workflow_data(wf) for wf in query.order_by(WorkflowModel.created_at.desc()).offset(offset).limit(limit)], "total": query.count(), "limit": limit, "offset": offset}


@router.get("/workflows/{workflow_id}", response_model=WorkflowDetail)
def get_workflow(workflow_id: str, db: Session = Depends(get_db)):
    wf = db.get(WorkflowModel, workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    return workflow_data(wf)


@router.get("/vulnerabilities/{finding_id}")
def finding_detail(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(VulnerabilityModel, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    data = row_data(finding)
    latest = db.query(PatchAttemptModel).filter_by(vulnerability_id=finding_id).order_by(PatchAttemptModel.created_at.desc(), PatchAttemptModel.id.desc()).first()
    data["latest_patch_id"] = latest.id if latest else None
    return data


@router.get("/patches")
def list_patches(workflow_id: str = None, vulnerability_id: str = None, status: str = None, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    query = db.query(PatchAttemptModel)
    for name, value in (("workflow_id", workflow_id), ("vulnerability_id", vulnerability_id), ("status", status)):
        if value is not None:
            query = query.filter(getattr(PatchAttemptModel, name) == value)
    return {"items": [patch_data(db, p) for p in query.order_by(PatchAttemptModel.created_at.desc()).offset(offset).limit(limit)], "total": query.count(), "limit": limit, "offset": offset}


@router.post("/patches/{patch_id}/approve", response_model=ReviewResponse)
def approve(patch_id: str, request: ReviewRequest, db: Session = Depends(get_db)):
    return row_data(record_review(db, patch_id, "APPROVED", request))


@router.post("/patches/{patch_id}/reject", response_model=ReviewResponse)
def reject(patch_id: str, request: ReviewRequest, db: Session = Depends(get_db)):
    return row_data(record_review(db, patch_id, "REJECTED", request))


@router.get("/reports/{workflow_id}")
def report(workflow_id: str, db: Session = Depends(get_db)):
    wf = db.get(WorkflowModel, workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    return workflow_report(db, wf)
