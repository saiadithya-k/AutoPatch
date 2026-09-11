"""AutoPatch Audit Service.

Central service for capturing, sanitizing, persisting, and querying lifecycle
audit events across scanning, risk assessment, context retrieval, patch generation,
validation, and bounded retry loops.
"""

import copy
import json
import logging
import re
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional, Union

from sqlalchemy.orm import Session

from backend.database.database import session_scope
from backend.database.models import AuditEventModel, utc_now
from backend.models.audit import AuditEventStatus, AuditEventType

logger = logging.getLogger(__name__)

# Patterns matching sensitive keys that must be redacted
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|api_?key|authorization|cookie|private_?key|(?:^|_|\b)token(?:$|_|\b))"
)

REDACTED_VALUE = "[REDACTED]"


def sanitize_metadata(data: Any) -> Any:
    """
    Recursively sanitize metadata structures to prevent leakage of credentials or secrets.

    - Replaces values of keys matching sensitive patterns with '[REDACTED]'.
    - Converts non-JSON-serializable objects (datetime, date, Path, Pydantic models) to serializable forms.
    - Never mutates input structures in-place.
    """
    if data is None:
        return None

    # Handle Pydantic models
    if hasattr(data, "model_dump"):
        data = data.model_dump()
    elif hasattr(data, "dict") and callable(getattr(data, "dict")):
        data = data.dict()

    if isinstance(data, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in data.items():
            key_str = str(k)
            if SENSITIVE_KEY_PATTERN.search(key_str):
                sanitized_dict[key_str] = REDACTED_VALUE
            else:
                sanitized_dict[key_str] = sanitize_metadata(v)
        return sanitized_dict

    elif isinstance(data, (list, tuple, set)):
        return [sanitize_metadata(item) for item in data]

    elif isinstance(data, (datetime, date)):
        return data.isoformat()

    elif isinstance(data, Path):
        return str(data)

    elif isinstance(data, (int, float, bool, str)):
        return data

    else:
        # Fallback to string representation for unfamiliar types
        return str(data)


class AuditService:
    """Service providing safe, centralized audit event recording and querying."""

    @staticmethod
    def _generate_event_id() -> str:
        """Generate unique audit event ID."""
        return f"AUDIT-{uuid.uuid4().hex[:10].upper()}"

    def record_event(
        self,
        event_type: Union[AuditEventType, str],
        workflow_id: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        patch_attempt_id: Optional[str] = None,
        validation_id: Optional[str] = None,
        event_status: Union[AuditEventStatus, str] = AuditEventStatus.SUCCESS,
        message: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        session: Optional[Session] = None,
    ) -> AuditEventModel:
        """
        Record a lifecycle audit event with automated metadata secret sanitization.

        :param event_type: Strongly typed event type or string name.
        :param workflow_id: Optional associated workflow run ID.
        :param vulnerability_id: Optional associated vulnerability ID.
        :param patch_attempt_id: Optional associated patch attempt ID.
        :param validation_id: Optional associated validation run ID.
        :param event_status: Execution status (SUCCESS, FAILED, WARNING, INFO).
        :param message: Human-readable narrative describing the event.
        :param metadata: Structured event metadata (automatically sanitized for secrets).
        :param session: Optional active SQLAlchemy session. If None, a new transaction scope is used.
        :return: Persisted AuditEventModel record.
        """
        # Resolve type strings
        ev_type_str = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
        ev_status_str = event_status.value if isinstance(event_status, AuditEventStatus) else str(event_status)

        # Sanitize metadata to eradicate secrets
        safe_meta = sanitize_metadata(metadata) if metadata is not None else {}

        event_id = self._generate_event_id()
        now = utc_now()

        event = AuditEventModel(
            id=event_id,
            workflow_id=workflow_id,
            vulnerability_id=vulnerability_id,
            patch_attempt_id=patch_attempt_id,
            validation_id=validation_id,
            event_type=ev_type_str,
            event_status=ev_status_str,
            message=message,
            created_at=now,
        )
        event.set_metadata(safe_meta)

        def _persist(db_sess: Session) -> None:
            db_sess.add(event)
            db_sess.flush()

        if session is not None:
            _persist(session)
        else:
            with session_scope() as new_session:
                _persist(new_session)

        logger.info(
            "Audit event recorded: [%s] %s (Workflow: %s, Vuln: %s, Patch: %s)",
            ev_status_str,
            ev_type_str,
            workflow_id or "N/A",
            vulnerability_id or "N/A",
            patch_attempt_id or "N/A",
        )
        return event

    def get_event(
        self,
        event_id: str,
        session: Session,
    ) -> Optional[AuditEventModel]:
        """Retrieve a single audit event record by its unique ID."""
        return session.query(AuditEventModel).filter(AuditEventModel.id == event_id).first()

    def list_events(
        self,
        session: Session,
        workflow_id: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        patch_attempt_id: Optional[str] = None,
        validation_id: Optional[str] = None,
        event_type: Optional[Union[AuditEventType, str]] = None,
        event_status: Optional[Union[AuditEventStatus, str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEventModel]:
        """List audit events matching the specified filter criteria, ordered by timestamp descending."""
        query = session.query(AuditEventModel)

        if workflow_id:
            query = query.filter(AuditEventModel.workflow_id == workflow_id)
        if vulnerability_id:
            query = query.filter(AuditEventModel.vulnerability_id == vulnerability_id)
        if patch_attempt_id:
            query = query.filter(AuditEventModel.patch_attempt_id == patch_attempt_id)
        if validation_id:
            query = query.filter(AuditEventModel.validation_id == validation_id)
        if event_type:
            ev_type_val = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
            query = query.filter(AuditEventModel.event_type == ev_type_val)
        if event_status:
            ev_status_val = event_status.value if isinstance(event_status, AuditEventStatus) else str(event_status)
            query = query.filter(AuditEventModel.event_status == ev_status_val)

        return (
            query.order_by(AuditEventModel.created_at.desc(), AuditEventModel.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def get_workflow_timeline(
        self,
        workflow_id: str,
        session: Session,
    ) -> list[AuditEventModel]:
        """
        Retrieve all audit events for a workflow in strict chronological order.
        Essential for lineage tracing and timeline reconstruction.
        """
        return (
            session.query(AuditEventModel)
            .filter(AuditEventModel.workflow_id == workflow_id)
            .order_by(AuditEventModel.created_at.asc(), AuditEventModel.id.asc())
            .all()
        )
