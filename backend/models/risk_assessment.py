"""Domain models and Pydantic schemas for Risk Assessment."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from backend.models.vulnerability import Severity, VulnerabilityFinding, WorkflowStatus


def get_utc_now() -> datetime:
    """Return timezone-naive UTC datetime."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class PriorityLevel(str, Enum):
    """Remediation priority tier."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AssessmentMethod(str, Enum):
    """Method used to compute the risk assessment."""
    DETERMINISTIC_RULES = "DETERMINISTIC_RULES"
    HYBRID_LLM = "HYBRID_LLM"
    LLM_REASONING = "LLM_REASONING"


class RiskContext(BaseModel):
    """Contextual metadata evaluated during risk calculation."""
    is_auth_involved: bool = Field(default=False, description="Whether authentication or authorization logic is affected")
    is_database_involved: bool = Field(default=False, description="Whether database or data storage is affected")
    is_remote_input: bool = Field(default=False, description="Whether untrusted external input is handled")
    is_code_execution: bool = Field(default=False, description="Whether dynamic code or shell execution is possible")
    is_sensitive_data: bool = Field(default=False, description="Whether sensitive data or secrets are exposed")
    is_test_file: bool = Field(default=False, description="Whether the finding resides in test code or mock fixtures")
    confidence_weight: float = Field(default=1.0, description="Confidence multiplier (0.5 - 1.0)")


class RiskAssessment(BaseModel):
    """Structured assessment record for a specific vulnerability finding."""
    id: str = Field(description="Unique risk assessment record identifier (e.g., RISK-xxxx)")
    vulnerability_id: str = Field(description="Associated vulnerability finding ID")
    workflow_id: Optional[str] = Field(default=None, description="Associated workflow run identifier")
    severity: Severity = Field(description="Normalized finding severity")
    severity_score: float = Field(description="Numerical severity component score (0.0 - 10.0)")
    exploitability: float = Field(description="Assessed exploitability metric (0.0 - 10.0)")
    business_impact: float = Field(description="Assessed business impact metric (0.0 - 10.0)")
    context_score: float = Field(description="Contextual modifier score (0.0 - 10.0)")
    risk_score: float = Field(description="Final aggregated risk score (0.0 - 10.0)")
    priority: PriorityLevel = Field(description="Derived remediation priority level")
    reasoning: str = Field(description="Human-readable transparent risk explanation")
    assessment_method: AssessmentMethod = Field(
        default=AssessmentMethod.DETERMINISTIC_RULES,
        description="Assessment methodology employed"
    )
    model: Optional[str] = Field(default=None, description="Optional LLM model identifier if used")
    context: Optional[RiskContext] = Field(default=None, description="Evaluated contextual factors")
    created_at: datetime = Field(default_factory=get_utc_now, description="Assessment creation timestamp")


class PrioritizedVulnerability(BaseModel):
    """Vulnerability finding enriched with risk assessment and prioritization rank."""
    vulnerability: VulnerabilityFinding = Field(description="Underlying normalized vulnerability finding")
    risk_assessment: RiskAssessment = Field(description="Associated risk assessment record")
    rank: int = Field(description="1-indexed remediation priority ranking")


class AssessRiskRequest(BaseModel):
    """Request payload for assessing risk across workflow findings."""
    workflow_id: Optional[str] = Field(default=None, description="Target workflow identifier")
    vulnerability_ids: Optional[list[str]] = Field(default=None, description="Optional subset of vulnerability IDs to evaluate")


class AssessRiskResponse(BaseModel):
    """Response payload returning prioritized vulnerabilities."""
    workflow_id: str = Field(description="Workflow execution run ID")
    status: WorkflowStatus = Field(description="Current status of the workflow")
    total_assessed: int = Field(description="Total number of evaluated findings")
    prioritized_vulnerabilities: list[PrioritizedVulnerability] = Field(
        default_factory=list,
        description="Ranked list of prioritized vulnerabilities (highest risk first)"
    )
