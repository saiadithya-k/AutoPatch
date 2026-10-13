"""Transactional review decisions; approval does not apply a patch."""
import uuid
import json
from fastapi import HTTPException
from sqlalchemy import update, exists, or_, and_
from sqlalchemy.exc import IntegrityError
from backend.database.models import PatchAttemptModel, ValidationResultModel, ReviewDecisionModel, WorkflowModel
from backend.services.audit import AuditService
from backend.services.reports import latest_candidates


def record_review(db, patch_id, decision, request):
    patch = db.get(PatchAttemptModel, patch_id)
    if patch is None:
        raise HTTPException(404, "Patch not found")
    existing = db.query(ReviewDecisionModel).filter_by(patch_attempt_id=patch_id).first()
    if existing:
        if existing.decision == decision and existing.reviewer_label == request.reviewer_label and existing.comment == request.comment:
            return existing
        raise HTTPException(409, "This proposal already has a review decision")
    if decision == "REJECTED" and not (request.comment or "").strip():
        raise HTTPException(422, "A rejection requires a comment")
    wf = db.get(WorkflowModel, patch.workflow_id) if patch.workflow_id else None
    if wf and wf.request_json and wf.completed_at is None:
        raise HTTPException(409, "Wait until the workflow finishes before reviewing its proposals")
    newer_condition = and_(PatchAttemptModel.vulnerability_id == patch.vulnerability_id, or_(PatchAttemptModel.created_at > patch.created_at, and_(PatchAttemptModel.created_at == patch.created_at, PatchAttemptModel.id > patch.id)))
    newer = db.query(PatchAttemptModel).filter(newer_condition).first()
    if newer:
        raise HTTPException(409, "A newer candidate exists; review the latest proposal")
    validation = db.query(ValidationResultModel).filter_by(patch_attempt_id=patch_id).order_by(ValidationResultModel.started_at.desc(), ValidationResultModel.id.desc()).first()
    try:
        coverage = json.loads(validation.scanner_metadata or "{}") if validation else {}
        if not isinstance(coverage, dict):
            raise ValueError("Invalid scanner metadata type")
    except (ValueError, TypeError):
        raise HTTPException(409, "Stored scanner evidence is malformed; validation must be repeated")
    eligible = bool(validation and validation.status == "PASSED" and validation.patch_applied and validation.syntax_check_passed and validation.tests_passed and validation.security_scan_passed and validation.original_vulnerability_resolved and validation.new_findings_count == 0 and not validation.regression_detected and coverage.get("coverage_complete") is True)
    if decision == "APPROVED" and not eligible:
        raise HTTPException(409, "Approval requires successful persisted validation evidence")
    if patch.status not in {"READY_FOR_REVIEW", "VALIDATED"}:
        raise HTTPException(409, "Only validated proposals awaiting review can be decided")
    try:
        constraints = [PatchAttemptModel.id == patch_id, PatchAttemptModel.status == patch.status, ~exists().where(newer_condition)]
        if validation:
            newer_validation = and_(ValidationResultModel.patch_attempt_id == patch_id, or_(ValidationResultModel.started_at > validation.started_at, and_(ValidationResultModel.started_at == validation.started_at, ValidationResultModel.id > validation.id)))
            constraints.append(~exists().where(newer_validation))
            if decision == "APPROVED":
                constraints.append(exists().where(ValidationResultModel.id == validation.id, ValidationResultModel.status == "PASSED", ValidationResultModel.patch_applied.is_(True), ValidationResultModel.syntax_check_passed.is_(True), ValidationResultModel.tests_passed.is_(True), ValidationResultModel.security_scan_passed.is_(True), ValidationResultModel.original_vulnerability_resolved.is_(True), ValidationResultModel.new_findings_count == 0, ValidationResultModel.scanner_metadata == validation.scanner_metadata, or_(ValidationResultModel.regression_detected.is_(False), ValidationResultModel.regression_detected.is_(None))))
        changed = db.execute(update(PatchAttemptModel).where(*constraints).values(status=decision)).rowcount
        if changed != 1:
            db.rollback()
            raise HTTPException(409, "Another reviewer changed this proposal")
        review = ReviewDecisionModel(id=f"review-{uuid.uuid4().hex}", patch_attempt_id=patch_id, validation_id=validation.id if validation else None, decision=decision, reviewer_label=request.reviewer_label, comment=request.comment)
        db.add(review)
        AuditService().record_event(f"PATCH_{decision}", workflow_id=patch.workflow_id, vulnerability_id=patch.vulnerability_id, patch_attempt_id=patch_id, validation_id=review.validation_id, message=f"Proposal {decision.lower()} by {request.reviewer_label}", session=db)
        wf = db.get(WorkflowModel, patch.workflow_id) if patch.workflow_id else None
        if wf and wf.completed_at:
            latest = latest_candidates(db.query(PatchAttemptModel).filter_by(workflow_id=wf.id).all())
            pending = sum(p.status in {"READY_FOR_REVIEW", "VALIDATED"} for p in latest.values())
            wf.reviewable_count = pending
            if pending == 0:
                decisions = db.query(ReviewDecisionModel).filter(ReviewDecisionModel.patch_attempt_id.in_([p.id for p in latest.values()])).all()
                approved = sum(r.decision == "APPROVED" for r in decisions)
                wf.status = "APPROVED" if approved == len(latest) else "REJECTED" if approved == 0 else "COMPLETED"
                wf.current_stage = "REVIEW_COMPLETE"
                wf.outcome = "REVIEW_COMPLETE_WITH_UNRESOLVED" if wf.failed_count or wf.processed_findings < wf.total_findings or approved != len(latest) else "PROPOSALS_APPROVED"
        db.commit()
        db.refresh(review)
        return review
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Another reviewer decided this proposal")
