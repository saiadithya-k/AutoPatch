"""Pydantic domain models for Patch Generation."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


def get_utc_now() -> datetime:
    """Return timezone-naive UTC datetime for consistent timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class PatchStatus(str, Enum):
    """Lifecycle states of a candidate patch."""
    GENERATED = "GENERATED"
    READY_FOR_VALIDATION = "READY_FOR_VALIDATION"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    FAILED_VALIDATION = "FAILED_VALIDATION"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    APPROVED = "APPROVED"
    NO_PROGRESS = "NO_PROGRESS"
    RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
    VALIDATION_FAILED = "VALIDATION_FAILED"


class PatchFileChange(BaseModel):
    """Detailed file-level code replacement block."""
    file_path: str = Field(description="Relative repository path of the modified file")
    start_line: int = Field(description="1-indexed starting line number of original code")
    end_line: int = Field(description="1-indexed ending line number of original code")
    original_code: str = Field(description="Original vulnerable code snippet")
    replacement_code: str = Field(description="New secure replacement code snippet")


class PatchGenerationRequest(BaseModel):
    """Request payload for triggering patch generation on a vulnerability."""
    vulnerability_id: Optional[str] = Field(default=None, description="Optional target vulnerability finding identifier")
    attempt_number: Optional[int] = Field(default=1, description="Patch generation iteration attempt number")
    feedback: Optional[str] = Field(default=None, description="Optional failure/retry feedback from validation")


class PatchGenerationResult(BaseModel):
    """Strongly typed candidate patch result generated for a vulnerability."""
    id: str = Field(description="Unique patch attempt identifier (e.g. PATCH-xxxx)")
    workflow_id: Optional[str] = Field(default=None, description="Associated workflow run identifier")
    vulnerability_id: str = Field(description="Associated vulnerability finding identifier")
    attempt_number: int = Field(default=1, description="Iteration attempt number")
    status: PatchStatus = Field(default=PatchStatus.GENERATED, description="Current patch lifecycle state")
    explanation: str = Field(description="Technical rationale explaining why the patch mitigates the flaw")
    unified_diff: str = Field(description="Candidate unified diff representation")
    changed_files: list[str] = Field(default_factory=list, description="List of relative file paths modified by patch")
    changes: list[PatchFileChange] = Field(default_factory=list, description="Structured change blocks")
    original_code: Optional[str] = Field(default=None, description="Extracted original code before patch")
    proposed_code: Optional[str] = Field(default=None, description="Extracted proposed replacement code")
    confidence: float = Field(default=0.9, description="Heuristic or model confidence score (0.0 - 1.0)")
    model: Optional[str] = Field(default=None, description="Model identifier used for patch generation")
    provider: Optional[str] = Field(default=None, description="LLM provider name used")
    feedback: Optional[str] = Field(default=None, description="Validation feedback incorporated if retrying")
    assumptions: list[str] = Field(default_factory=list, description="Assumptions made by the model")
    tests_to_run: list[str] = Field(default_factory=list, description="Recommended tests to run")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal warnings or validation notices")
    parent_patch_id: Optional[str] = Field(default=None, description="Identifier of previous patch attempt in retry chain")
    retry_reason: Optional[str] = Field(default=None, description="Reason for retry if this is an attempt > 1")
    validation_id: Optional[str] = Field(default=None, description="Identifier of previous validation run triggering this attempt")
    retryable: bool = Field(default=True, description="True if failure is considered retryable")
    generated_at: datetime = Field(default_factory=get_utc_now, description="Patch generation timestamp")


class PatchAttemptResponse(BaseModel):
    """API response model for patch attempt history records."""
    id: str
    workflow_id: Optional[str] = None
    vulnerability_id: str
    attempt_number: int
    patch_format: str = "unified_diff"
    patch_content: str
    explanation: Optional[str] = None
    files_changed: list[str] = Field(default_factory=list)
    generation_model: Optional[str] = None
    status: PatchStatus
    parent_patch_id: Optional[str] = None
    retry_reason: Optional[str] = None
    validation_id: Optional[str] = None
    retryable: bool = True
    review: Optional[dict[str, Any]] = None
    evidence_errors: list[dict[str, Any]] = Field(default_factory=list)
    failure_category: Optional[str] = None
    retry_decision: Optional[dict[str, Any]] = None
    created_at: datetime
