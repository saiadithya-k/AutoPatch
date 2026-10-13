"""Public workflow and review contracts."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class WorkflowCreate(BaseModel):
    repository_path: str = Field(min_length=1)
    max_retries: Optional[int] = Field(default=None, ge=0, le=10)
    max_findings: int = Field(default=10, ge=1, le=100)
    minimum_priority: str = "LOW"

    @field_validator("minimum_priority")
    @classmethod
    def valid_priority(cls, value):
        value = value.upper()
        if value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Priority must be LOW, MEDIUM, HIGH, or CRITICAL")
        return value


class WorkflowCreated(BaseModel):
    id: str
    status: str
    detail_url: str


class WorkflowDetail(BaseModel):
    id: str
    repository_path: str
    repository_url: Optional[str] = None
    branch: Optional[str] = None
    status: str
    current_stage: Optional[str] = None
    max_retries: int
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    processed_findings: int = 0
    total_findings: int = 0
    reviewable_count: int = 0
    failed_count: int = 0
    outcome: Optional[str] = None
    errors: list[str] = Field(default_factory=list)
    scan_metadata: dict = Field(default_factory=dict)
    evidence_errors: list[dict] = Field(default_factory=list)


class ReviewRequest(BaseModel):
    reviewer_label: str = Field(min_length=1, max_length=100)
    comment: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("reviewer_label")
    @classmethod
    def nonempty_reviewer(cls, value):
        if not value.strip():
            raise ValueError("Reviewer label cannot be blank")
        return value.strip()


class ReviewResponse(BaseModel):
    id: str
    patch_attempt_id: str
    validation_id: Optional[str] = None
    decision: str
    reviewer_label: str
    comment: Optional[str] = None
    created_at: datetime
