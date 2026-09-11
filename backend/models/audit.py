"""Pydantic schemas and enums for AutoPatch lifecycle audit events."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuditEventType(str, Enum):
    """Strongly typed lifecycle event types across the AutoPatch remediation pipeline."""

    # Workflow level
    WORKFLOW_CREATED = "WORKFLOW_CREATED"

    # Static Scanning
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_DEGRADED = "SCAN_DEGRADED"
    SCAN_FAILED = "SCAN_FAILED"

    # Risk Assessment
    RISK_ASSESSMENT_STARTED = "RISK_ASSESSMENT_STARTED"
    RISK_ASSESSMENT_COMPLETED = "RISK_ASSESSMENT_COMPLETED"
    RISK_ASSESSMENT_FAILED = "RISK_ASSESSMENT_FAILED"

    # Context Service
    CONTEXT_CREATED = "CONTEXT_CREATED"
    CONTEXT_FAILED = "CONTEXT_FAILED"

    # Patch Generation
    PATCH_GENERATION_STARTED = "PATCH_GENERATION_STARTED"
    PATCH_GENERATED = "PATCH_GENERATED"
    PATCH_GENERATION_FAILED = "PATCH_GENERATION_FAILED"

    # Patch Validation
    PATCH_VALIDATION_STARTED = "PATCH_VALIDATION_STARTED"
    PATCH_APPLIED = "PATCH_APPLIED"
    PATCH_VALIDATION_FAILED = "PATCH_VALIDATION_FAILED"
    PATCH_VALIDATED = "PATCH_VALIDATED"

    # Retry Loop
    RETRY_DECISION = "RETRY_DECISION"
    RETRY_STARTED = "RETRY_STARTED"
    RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
    NO_PROGRESS = "NO_PROGRESS"

    # Human Review Boundary (Hard boundary — no auto-merge or auto-approval)
    READY_FOR_REVIEW = "READY_FOR_REVIEW"

    # System
    SYSTEM_ERROR = "SYSTEM_ERROR"


class AuditEventStatus(str, Enum):
    """Operational status of an individual audit event."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    WARNING = "WARNING"
    INFO = "INFO"


class AuditEventRecord(BaseModel):
    """Pydantic model representing a persistent lifecycle audit event record."""

    id: str = Field(description="Unique audit event identifier (AUDIT-XXXX)")
    workflow_id: Optional[str] = Field(default=None, description="Associated workflow identifier")
    vulnerability_id: Optional[str] = Field(default=None, description="Associated vulnerability identifier")
    patch_attempt_id: Optional[str] = Field(default=None, description="Associated patch attempt identifier")
    validation_id: Optional[str] = Field(default=None, description="Associated validation result identifier")
    event_type: AuditEventType = Field(description="Strongly typed event categorization")
    event_status: AuditEventStatus = Field(default=AuditEventStatus.SUCCESS, description="Execution status")
    message: Optional[str] = Field(default=None, description="Human-readable event summary")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Sanitized event metadata")
    created_at: datetime = Field(description="Timestamp when event was recorded (UTC)")

    model_config = ConfigDict(from_attributes=True)


class AuditEventFilter(BaseModel):
    """Query filter parameters for listing audit events."""

    workflow_id: Optional[str] = None
    vulnerability_id: Optional[str] = None
    patch_attempt_id: Optional[str] = None
    validation_id: Optional[str] = None
    event_type: Optional[AuditEventType] = None
    event_status: Optional[AuditEventStatus] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class WorkflowAuditTimeline(BaseModel):
    """Chronological event timeline for a specific workflow."""

    workflow_id: str = Field(description="Workflow identifier")
    total_events: int = Field(description="Total count of audit events in timeline")
    events: list[AuditEventRecord] = Field(description="Chronologically ordered audit event records")
