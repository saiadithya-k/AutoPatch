"""SQLAlchemy ORM models for AutoPatch entities."""

import json
from datetime import datetime, timezone
from typing import Any, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from backend.database.database import Base


def utc_now() -> datetime:
    """Return timezone-naive UTC datetime for SQLite compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class WorkflowModel(Base):
    """SQLAlchemy model representing an AutoPatch workflow execution run."""

    __tablename__ = "workflows"

    id = Column(String, primary_key=True, index=True)
    repository_path = Column(String, nullable=False)
    repository_url = Column(String, nullable=True)
    branch = Column(String, nullable=True)
    status = Column(String, nullable=False, default="CREATED", index=True)
    current_stage = Column(String, nullable=True)
    max_retries = Column(Integer, default=3, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    vulnerabilities = relationship(
        "VulnerabilityModel",
        back_populates="workflow",
        cascade="all, delete-orphan",
        order_by="VulnerabilityModel.created_at"
    )
    risk_assessments = relationship(
        "RiskAssessmentModel",
        back_populates="workflow",
        cascade="all, delete-orphan"
    )
    patch_attempts = relationship(
        "PatchAttemptModel",
        back_populates="workflow",
        cascade="all, delete-orphan"
    )


class VulnerabilityModel(Base):
    """SQLAlchemy model representing a security vulnerability finding."""

    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, index=True)
    workflow_id = Column(String, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    tool = Column(String, nullable=False)
    rule_id = Column(String, nullable=True)
    type = Column(String, nullable=False)
    cwe = Column(String, nullable=True)
    severity = Column(String, nullable=False, index=True)
    confidence = Column(String, nullable=True)
    file_path = Column(String, nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    raw_finding = Column(Text, nullable=True)
    exploitability = Column(Float, nullable=True)
    business_impact = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=True, index=True)
    priority = Column(String, nullable=True, index=True)
    risk_reasoning = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="DETECTED", index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    workflow = relationship("WorkflowModel", back_populates="vulnerabilities")
    risk_assessments = relationship(
        "RiskAssessmentModel",
        back_populates="vulnerability",
        cascade="all, delete-orphan"
    )
    patch_attempts = relationship(
        "PatchAttemptModel",
        back_populates="vulnerability",
        cascade="all, delete-orphan"
    )

    def set_raw_finding(self, data: dict) -> None:
        """Store raw scanner finding dictionary as JSON string."""
        self.raw_finding = json.dumps(data) if data else None

    def get_raw_finding(self) -> dict:
        """Retrieve raw scanner finding dictionary."""
        return json.loads(self.raw_finding) if self.raw_finding else {}


class RiskAssessmentModel(Base):
    """SQLAlchemy model representing a detailed risk assessment for a vulnerability."""

    __tablename__ = "risk_assessments"

    id = Column(String, primary_key=True, index=True)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    workflow_id = Column(String, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=True, index=True)
    severity = Column(String, nullable=False)
    severity_score = Column(Float, nullable=False, default=0.0)
    exploitability = Column(Float, nullable=False)
    business_impact = Column(Float, nullable=False)
    context_score = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=False, index=True)
    priority = Column(String, nullable=False, index=True)
    reasoning = Column(Text, nullable=False)
    assessment_method = Column(String, nullable=False, default="DETERMINISTIC_RULES")
    model = Column(String, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    vulnerability = relationship("VulnerabilityModel", back_populates="risk_assessments")
    workflow = relationship("WorkflowModel", back_populates="risk_assessments")


class PatchAttemptModel(Base):
    """SQLAlchemy model representing a candidate patch attempt generated for a vulnerability."""

    __tablename__ = "patch_attempts"

    id = Column(String, primary_key=True, index=True)
    workflow_id = Column(String, ForeignKey("workflows.id", ondelete="CASCADE"), nullable=True, index=True)
    vulnerability_id = Column(String, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_patch_id = Column(String, ForeignKey("patch_attempts.id", ondelete="SET NULL"), nullable=True, index=True)
    attempt_number = Column(Integer, default=1, nullable=False)
    patch_format = Column(String, default="unified_diff", nullable=False)
    patch_content = Column(Text, nullable=False)
    explanation = Column(Text, nullable=True)
    files_changed = Column(Text, nullable=True)
    generation_model = Column(String, nullable=True)
    generation_metadata = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="GENERATED", index=True)
    retry_reason = Column(Text, nullable=True)
    validation_id = Column(String, nullable=True)
    retryable = Column(Boolean, default=True, nullable=False)
    failure_category = Column(String, nullable=True, index=True)
    retry_decision = Column(Text, nullable=True)  # JSON-serialized RetryDecision
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    vulnerability = relationship("VulnerabilityModel", back_populates="patch_attempts")
    workflow = relationship("WorkflowModel", back_populates="patch_attempts")
    parent_patch = relationship("PatchAttemptModel", remote_side=[id], backref="child_patches")
    validation_results = relationship(
        "ValidationResultModel",
        back_populates="patch_attempt",
        cascade="all, delete-orphan",
        order_by="ValidationResultModel.started_at.asc()",
    )

    def set_files_changed(self, files: list[str]) -> None:
        self.files_changed = json.dumps(files) if files else "[]"

    def get_files_changed(self) -> list[str]:
        return json.loads(self.files_changed) if self.files_changed else []

    def set_retry_decision(self, decision_data: Any) -> None:
        """Store RetryDecision as JSON string."""
        if decision_data is None:
            self.retry_decision = None
        elif isinstance(decision_data, str):
            self.retry_decision = decision_data
        elif hasattr(decision_data, "model_dump_json"):
            self.retry_decision = decision_data.model_dump_json()
        elif hasattr(decision_data, "model_dump"):
            self.retry_decision = json.dumps(decision_data.model_dump())
        elif isinstance(decision_data, dict):
            self.retry_decision = json.dumps(decision_data)

    def get_retry_decision(self) -> Optional[dict]:
        """Retrieve stored RetryDecision as a dictionary."""
        return json.loads(self.retry_decision) if self.retry_decision else None


class ValidationResultModel(Base):
    """SQLAlchemy model representing a candidate patch validation run and its verification evidence."""

    __tablename__ = "validation_results"

    id = Column(String, primary_key=True, index=True)
    patch_attempt_id = Column(String, ForeignKey("patch_attempts.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String, nullable=False, default="RUNNING", index=True)
    patch_applied = Column(Boolean, default=False, nullable=False)
    syntax_check_passed = Column(Boolean, default=False, nullable=False)
    tests_passed = Column(Boolean, default=False, nullable=False)
    tests_run = Column(Integer, nullable=True)
    test_exit_code = Column(Integer, nullable=True)
    test_stdout = Column(Text, nullable=True)
    test_stderr = Column(Text, nullable=True)
    security_scan_passed = Column(Boolean, default=False, nullable=False)
    original_vulnerability_resolved = Column(Boolean, default=False, nullable=False)
    new_findings_count = Column(Integer, default=0, nullable=False)
    new_findings = Column(Text, nullable=True)  # JSON serialized list of new findings
    regression_detected = Column(Boolean, nullable=True)
    failure_reason = Column(Text, nullable=True)
    failure_category = Column(String, nullable=True, index=True)
    validation_logs = Column(Text, nullable=True)
    sandbox_type = Column(String, default="local_workspace_dev_fallback", nullable=True)
    duration = Column(Float, default=0.0, nullable=False)
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    patch_attempt = relationship("PatchAttemptModel", back_populates="validation_results")

