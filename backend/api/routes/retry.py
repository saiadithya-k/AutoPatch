import json
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.agents.retry_agent import RetryAgent
from backend.database.database import get_db
from backend.database.models import PatchAttemptModel, ValidationResultModel
from backend.models.retry import RetryAttemptRecord, RetryDecision, RetryLoopResult

router = APIRouter(prefix="/api", tags=["Patch Retry Loop"])


@router.post(
    "/patches/{patch_id}/retry",
    response_model=RetryLoopResult,
    status_code=status.HTTP_200_OK,
    summary="Execute bounded patch retry loop for candidate patch",
    description="Validates the patch attempt. If validation fails, analyzes failure evidence, determines retryability, generates an improved patch candidate, and re-validates up to MAX_PATCH_RETRIES."
)
def run_patch_retry_endpoint(
    patch_id: str,
    max_retries: Optional[int] = Query(None, ge=1, le=10, description="Override maximum additional retries (default 3)"),
    db: Session = Depends(get_db),
) -> RetryLoopResult:
    """Run bounded patch retry loop."""
    patch_rec = db.query(PatchAttemptModel).filter(
        PatchAttemptModel.id == patch_id
    ).first()

    if not patch_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch attempt '{patch_id}' not found."
        )

    agent = RetryAgent(max_retries=max_retries)
    try:
        result = agent.run_retry_loop(
            initial_patch_id=patch_id,
            max_retries=max_retries,
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
            detail=f"Retry loop execution failure: {str(e)}",
        )


@router.get(
    "/patches/{patch_id}/retry-history",
    response_model=list[RetryAttemptRecord],
    status_code=status.HTTP_200_OK,
    summary="Get complete retry history for a patch attempt and its ancestors/descendants",
    description="Returns the chronological sequence of patch attempts, parent IDs, validation IDs, failure reasons, and timestamps."
)
def get_patch_retry_history_endpoint(
    patch_id: str,
    db: Session = Depends(get_db),
) -> list[RetryAttemptRecord]:
    """Retrieve full audit lineage of retry attempts for a patch family."""
    patch_rec = db.query(PatchAttemptModel).filter(
        PatchAttemptModel.id == patch_id
    ).first()

    if not patch_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch attempt '{patch_id}' not found."
        )

    # 1. Trace back to root ancestor with cycle detection
    root = patch_rec
    visited = {patch_rec.id}
    while root.parent_patch_id and root.parent_patch_id not in visited:
        visited.add(root.parent_patch_id)
        parent = db.query(PatchAttemptModel).filter(
            PatchAttemptModel.id == root.parent_patch_id
        ).first()
        if not parent or parent.id == root.id:
            break
        root = parent

    # 2. Collect all descendant attempts from root
    all_attempts: list[PatchAttemptModel] = []
    to_visit = [root]
    seen_ids = set()

    while to_visit:
        curr = to_visit.pop(0)
        if curr.id in seen_ids:
            continue
        seen_ids.add(curr.id)
        all_attempts.append(curr)

        children = db.query(PatchAttemptModel).filter(
            PatchAttemptModel.parent_patch_id == curr.id
        ).all()
        for ch in children:
            if ch.id not in seen_ids:
                to_visit.append(ch)

    # Sort attempts monotonically by attempt_number, then created_at
    all_attempts.sort(key=lambda a: (a.attempt_number or 1, a.created_at))

    # Format into RetryAttemptRecord items
    history: list[RetryAttemptRecord] = []
    for att in all_attempts:
        # Load validation result if present
        val_rec = None
        if att.validation_id:
            val_rec = db.query(ValidationResultModel).filter(
                ValidationResultModel.id == att.validation_id
            ).first()
        if not val_rec:
            # Fallback to querying by patch_attempt_id
            val_rec = db.query(ValidationResultModel).filter(
                ValidationResultModel.patch_attempt_id == att.id
            ).order_by(ValidationResultModel.started_at.desc()).first()

        val_id = val_rec.id if val_rec else att.validation_id
        fail_reason = val_rec.failure_reason if val_rec else att.retry_reason
        val_status = val_rec.status if val_rec else att.status

        # Parse stored RetryDecision JSON safely
        parsed_decision: Optional[RetryDecision] = None
        if att.retry_decision:
            try:
                parsed_decision = RetryDecision.model_validate_json(att.retry_decision)
            except Exception:
                try:
                    parsed_decision = RetryDecision.model_validate(json.loads(att.retry_decision))
                except Exception:
                    parsed_decision = None

        # Resolve structured failure category
        fail_category = (
            att.failure_category
            or (parsed_decision.failure_category.value if parsed_decision else None)
            or (val_rec.failure_category if val_rec else None)
        )

        history.append(
            RetryAttemptRecord(
                attempt_number=att.attempt_number or 1,
                patch_id=att.id,
                parent_patch_id=att.parent_patch_id,
                validation_id=val_id,
                status=val_status or att.status,
                failure_reason=fail_reason,
                failure_category=fail_category,
                retry_decision=parsed_decision,
                created_at=att.created_at,
            )
        )

    return history
