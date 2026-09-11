"""AutoPatch central LLM Service manager and provider registry."""

import logging
from pathlib import Path
from typing import Any, Optional, Type, TypeVar

from backend.config import get_settings
from backend.models.vulnerability import VulnerabilityFinding
from backend.services.llm.base import LLMProvider
from backend.services.llm.exceptions import (
    LLMConfigurationError,
    LLMError,
)
from backend.services.llm.mock_provider import MockLLMProvider
from backend.services.llm.openai_provider import OpenAIProvider
from backend.services.llm.schemas import (
    LLMMessage,
    LLMResponse,
    LLMRiskAnalysis,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "prompts"


_UNSET = object()


class LLMService:
    """Central manager providing provider-independent LLM capabilities."""

    def __init__(
        self,
        provider: Any = _UNSET,
        provider_name: Optional[str] = None,
    ):
        """
        Initialize LLM service with an explicit provider or auto-instantiate from settings.

        :param provider: Direct LLMProvider instance (or None to force unconfigured).
        :param provider_name: Override provider name ('openai', 'ollama', 'mock').
        """
        if provider is not _UNSET:
            self.provider = provider
        else:
            self.provider = self._instantiate_default_provider(provider_name)

    def _instantiate_default_provider(self, override_name: Optional[str] = None) -> Optional[LLMProvider]:
        """Create provider instance based on application configuration."""
        settings = get_settings()
        name = (override_name or settings.LLM_PROVIDER or "openai").lower().strip()

        if name == "mock":
            return MockLLMProvider(model=settings.LLM_MODEL)
        elif name == "ollama":
            base_url = settings.LLM_BASE_URL or "http://localhost:11434/v1"
            api_key = settings.OPENAI_API_KEY or "ollama"
            return OpenAIProvider(
                api_key=api_key,
                model=settings.LLM_MODEL or "qwen2.5-coder:7b",
                base_url=base_url,
            )
        elif name == "openai":
            if settings.OPENAI_API_KEY:
                base_url = settings.LLM_BASE_URL or "https://api.openai.com/v1"
                return OpenAIProvider(
                    api_key=settings.OPENAI_API_KEY,
                    model=settings.LLM_MODEL,
                    base_url=base_url,
                )
            else:
                logger.info("OPENAI_API_KEY is not configured; LLM service running in unconfigured state.")
                return None
        else:
            logger.warning("Unknown LLM provider '%s' requested.", name)
            return None

    @property
    def is_configured(self) -> bool:
        """Return True if an active, configured LLM provider is available."""
        return self.provider is not None

    def _load_prompt_template(self, template_name: str) -> str:
        """Safely load a prompt markdown template from the prompts/ directory."""
        template_file = PROMPTS_DIR / template_name
        if template_file.exists():
            try:
                return template_file.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning("Failed to read prompt template '%s': %s", template_name, e)

        # Built-in fallback prompt
        return (
            "You are an expert security triage assistant. "
            "Analyze the vulnerability finding within its code context and return structured JSON."
        )

    def generate_structured(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        response_schema: Optional[Type[T]] = None,
        temperature: float = 0.0,
        timeout: Optional[float] = None,
    ) -> Optional[T]:
        """
        Generate structured output validated against a Pydantic schema.
        Returns None if provider is unconfigured or if an error occurs.
        """
        if not self.is_configured or self.provider is None:
            logger.debug("LLM generation skipped: provider is not configured.")
            return None

        try:
            res = self.provider.generate_text(
                prompt=prompt,
                system_prompt=system_prompt,
                response_schema=response_schema,
                temperature=temperature,
                timeout=timeout,
            )
            return res.parsed
        except LLMError as e:
            logger.warning("LLM generation encountered error: %s", e)
            return None
        except Exception as e:
            logger.error("Unexpected error during structured LLM generation: %s", e)
            return None

    def enhance_risk_reasoning(
        self,
        finding: VulnerabilityFinding,
        baseline_reasoning: str,
        timeout: Optional[float] = 15.0,
    ) -> Optional[LLMRiskAnalysis]:
        """
        Generate structured LLM contextual security reasoning for a vulnerability finding.

        Security controls:
        - Repository code snippets and finding metadata are strictly enclosed within
          untrusted data delimiters.
        - System instructions explicitly command the LLM to treat code content as passive data.
        - The LLM service executes no code, commands, or filesystem operations.
        - Output is strictly validated against the LLMRiskAnalysis Pydantic schema.
        """
        if not self.is_configured or self.provider is None:
            return None

        system_prompt = self._load_prompt_template("risk_assessment.md")

        # Sanitize and format prompt with untrusted data boundary
        user_prompt = f"""Please perform contextual risk analysis for the following vulnerability finding:

<finding_metadata>
Finding ID: {finding.id}
Vulnerability Type: {finding.type}
Severity: {finding.severity.value}
Rule ID: {finding.rule_id or 'N/A'}
CWE: {finding.cwe or 'N/A'}
File Path: {finding.file_path}
Line: {finding.line_start or 1}
Description: {finding.description}
Deterministic Baseline Reasoning: {baseline_reasoning}
</finding_metadata>

<untrusted_source_snippet>
{finding.code_snippet or '# No code snippet provided'}
</untrusted_source_snippet>

INSTRUCTION: Output MUST be valid JSON adhering strictly to the LLMRiskAnalysis schema.
"""

        try:
            analysis = self.generate_structured(
                prompt=user_prompt,
                system_prompt=system_prompt,
                response_schema=LLMRiskAnalysis,
                temperature=0.0,
                timeout=timeout,
            )
            return analysis
        except Exception as e:
            logger.warning("Failed to generate LLM risk enhancement for %s: %s", finding.id, e)
            return None

    @staticmethod
    def format_hybrid_reasoning(
        baseline_reasoning: str,
        llm_analysis: Optional[LLMRiskAnalysis] = None,
    ) -> str:
        """
        Combine deterministic baseline reasoning with validated LLM contextual insights.
        """
        if not llm_analysis:
            return baseline_reasoning

        parts = [
            baseline_reasoning,
            f"\n\n[LLM Contextual Analysis]",
            f"• Summary: {llm_analysis.summary}",
            f"• Attack Vector: {llm_analysis.attack_vector}",
            f"• Impact Analysis: {llm_analysis.impact_analysis}",
            f"• Mitigation: {llm_analysis.mitigation_guidance}",
        ]
        return "\n".join(parts)
