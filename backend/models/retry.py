"""Pydantic domain models for Patch Retry Loop and Decision Policy."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


def get_utc_now() -> datetime:
    """Return timezone-naive UTC datetime for consistent timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class RetryStatus(str, Enum):
    """Explicit workflow states for the bounded patch retry loop."""
    PATCH_GENERATING = "PATCH_GENERATING"
    PATCH_GENERATED = "PATCH_GENERATED"
    VALIDATING = "VALIDATING"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    RETRY_DECISION = "RETRY_DECISION"
    RETRY_GENERATING = "RETRY_GENERATING"
    VALIDATED = "VALIDATED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
    NO_PROGRESS = "NO_PROGRESS"
    FAILED = "FAILED"


class FailureCategory(str, Enum):
    """Categorization of validation failures to govern retry policy."""
    PATCH_APPLICATION_FAILED = "PATCH_APPLICATION_FAILED"
    SYNTAX_ERROR = "SYNTAX_ERROR"
    TEST_FAILURE = "TEST_FAILURE"
    UNRESOLVED_VULNERABILITY = "UNRESOLVED_VULNERABILITY"
    NEW_VULNERABILITY = "NEW_VULNERABILITY"
    SECURITY_REGRESSION = "SECURITY_REGRESSION"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"
    DOCKER_UNAVAILABLE = "DOCKER_UNAVAILABLE"
    REPEATED_PATCH = "REPEATED_PATCH"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"


class RetryDecision(BaseModel):
    """Deterministic policy decision on whether a failed patch attempt should be retried."""
    should_retry: bool = Field(description="True if failure category is retryable and retry budget remains")
    reason: str = Field(description="Actionable explanation of the retry decision")
    failure_category: FailureCategory = Field(description="Classified failure category")
    can_retry_further: bool = Field(default=True, description="True if retry attempt budget has not been exhausted")


class RetryAttemptRecord(BaseModel):
    """Structured audit record for a single patch attempt in the retry chain."""
    attempt_number: int = Field(description="Attempt index (1 for initial, 2+ for retries)")
    patch_id: str = Field(description="PatchAttempt identifier")
    parent_patch_id: Optional[str] = Field(default=None, description="Identifier of predecessor patch attempt")
    validation_id: Optional[str] = Field(default=None, description="Validation run identifier")
    status: str = Field(description="Status of this patch attempt after validation")
    failure_reason: Optional[str] = Field(default=None, description="Reason for validation failure if failed")
    failure_category: Optional[str] = Field(default=None, description="Categorized failure type if applicable")
    retry_decision: Optional[RetryDecision] = Field(default=None, description="Retry evaluation decision")
    created_at: datetime = Field(default_factory=get_utc_now, description="Timestamp of attempt creation")


class RetryLoopResult(BaseModel):
    """Comprehensive outcome of the bounded patch retry loop execution."""
    status: str = Field(description="Final terminal state (e.g. READY_FOR_REVIEW, RETRY_EXHAUSTED, NO_PROGRESS)")
    vulnerability_id: str = Field(description="Target vulnerability finding identifier")
    workflow_id: Optional[str] = Field(default=None, description="Associated workflow run identifier")
    initial_patch_id: str = Field(description="Identifier of the initial patch attempt")
    successful_patch_id: Optional[str] = Field(default=None, description="Identifier of the validated patch if successful")
    total_attempts: int = Field(description="Total number of attempts executed in this loop")
    attempts: list[RetryAttemptRecord] = Field(default_factory=list, description="Chronological audit chain of attempts")
    last_validation_id: Optional[str] = Field(default=None, description="Validation ID of the final attempt")
    final_failure_reason: Optional[str] = Field(default=None, description="Failure reason if loop did not succeed")
    recommendation: str = Field(description="Actionable next step recommendation for developers")
