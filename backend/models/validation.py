"""Pydantic domain models for Patch Validation."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


def get_utc_now() -> datetime:
    """Return timezone-naive UTC datetime for consistent timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ValidationStatus(str, Enum):
    """Lifecycle states of a patch validation run."""
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class SecurityComparisonResult(BaseModel):
    """Detailed differential security analysis before and after patch application."""
    original_vulnerability_resolved: bool = Field(
        description="True if the targeted vulnerability finding is no longer detected after patching"
    )
    remaining_original_findings_count: int = Field(
        default=0,
        description="Number of findings matching original vulnerability still present"
    )
    new_findings_count: int = Field(
        default=0,
        description="Number of newly introduced security findings not present in baseline scan"
    )
    new_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of newly introduced vulnerability findings"
    )
    security_scan_passed: bool = Field(
        description="True if original vulnerability is resolved and zero new vulnerabilities were introduced"
    )


class ValidationResult(BaseModel):
    """Comprehensive, structured candidate patch validation verdict and evidence."""
    id: str = Field(description="Unique validation execution identifier (e.g. VAL-xxxx)")
    patch_attempt_id: str = Field(description="Associated PatchAttempt identifier")
    vulnerability_id: str = Field(description="Associated VulnerabilityFinding identifier")
    workflow_id: Optional[str] = Field(default=None, description="Associated workflow identifier")
    status: ValidationStatus = Field(description="Overall validation verdict")
    patch_applied: bool = Field(default=False, description="True if patch applied cleanly to workspace")
    syntax_check_passed: bool = Field(default=False, description="True if workspace compiled without syntax errors")
    tests_passed: bool = Field(default=False, description="True if project test suite passed")
    tests_run: Optional[int] = Field(default=0, description="Total number of tests executed")
    test_exit_code: Optional[int] = Field(default=None, description="Test runner process return code")
    test_stdout: Optional[str] = Field(default=None, description="Test runner captured standard output")
    test_stderr: Optional[str] = Field(default=None, description="Test runner captured standard error")
    security_scan_passed: bool = Field(
        default=False,
        description="True if security re-scan confirmed mitigation without new findings"
    )
    original_vulnerability_resolved: bool = Field(
        default=False,
        description="True if original vulnerability is confirmed mitigated"
    )
    new_findings_count: int = Field(default=0, description="Count of new security findings detected")
    new_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Serialized list of newly introduced findings"
    )
    regression_detected: bool = Field(
        default=False,
        description="True if tests failed or new vulnerabilities were introduced"
    )
    failure_reason: Optional[str] = Field(
        default=None,
        description="Clear, actionable rationale explaining why validation failed"
    )
    failure_category: Optional[str] = Field(
        default=None,
        description="Machine-readable structured failure category (e.g. FailureCategory enum value)"
    )
    validation_logs: Optional[str] = Field(
        default=None,
        description="Consolidated step-by-step validation execution log"
    )
    sandbox_type: str = Field(default="local_workspace", description="Sandbox executor type utilized")
    duration: float = Field(default=0.0, description="Total validation duration in seconds")
    started_at: datetime = Field(default_factory=get_utc_now, description="Validation start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Validation completion timestamp")
