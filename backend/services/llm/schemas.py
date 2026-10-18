"""AutoPatch structured LLM request and response Pydantic schemas."""

from typing import Any, Generic, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class LLMMessage(BaseModel):
    """Chat completion message."""
    role: str = Field(description="Message role: 'system', 'user', or 'assistant'")
    content: str = Field(description="Textual message content")


class LLMResponse(BaseModel):
    """Structured envelope wrapping raw and validated LLM responses."""
    content: str = Field(description="Raw text content produced by the model")
    parsed: Optional[Any] = Field(default=None, description="Validated Pydantic model instance if schema was provided")
    model: str = Field(default="", description="Model identifier used for inference")
    usage: dict[str, Any] = Field(default_factory=dict, description="Token usage statistics")
    raw_response: Optional[dict[str, Any]] = Field(default=None, description="Raw provider response payload")


class LLMRiskAnalysis(BaseModel):
    """Structured contextual security analysis produced by LLM for a vulnerability."""
    summary: str = Field(
        description="Concise, clear explanation of the identified vulnerability in context"
    )
    attack_vector: str = Field(
        description="Technical description of how an adversary could exploit this finding"
    )
    impact_analysis: str = Field(
        description="Detailed assessment of data, system, or business consequences"
    )
    mitigation_guidance: str = Field(
        description="Actionable architectural and code-level remediation advice"
    )
    confidence_assessment: str = Field(
        description="Assessment of finding validity and false-positive likelihood"
    )


class LLMCodeChange(BaseModel):
    """Structured code replacement block."""
    file_path: str = Field(description="Target relative file path to modify")
    start_line: int = Field(description="1-indexed line number where replacement begins")
    end_line: int = Field(description="1-indexed line number where replacement ends")
    original_code: str = Field(min_length=1, description="Exact nonempty original code snippet being replaced, including indentation")
    replacement_code: str = Field(description="New secure replacement code snippet")


class LLMPatchGeneration(BaseModel):
    """Structured LLM output for automated patch generation."""
    explanation: str = Field(
        description="Technical explanation of how the patch fixes the security vulnerability without breaking functionality"
    )
    changes: list[LLMCodeChange] = Field(
        default_factory=list,
        description="List of precise, minimal file modifications"
    )
    unified_diff: Optional[str] = Field(
        default=None,
        description="Standard unified diff representation (e.g. --- a/file.py +++ b/file.py)"
    )
    assumptions: list[str] = Field(
        default_factory=list,
        description="Assumptions made regarding imports, environment, or execution flow"
    )
    tests_to_run: list[str] = Field(
        default_factory=list,
        description="Names of related test functions or test files to validate this patch"
    )
