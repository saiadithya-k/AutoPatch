"""AutoPatch LLM Service package.

Provides provider-independent LLM abstractions, structured output validation,
and safe prompt-injection resistant workflows.
"""

from backend.services.llm.base import LLMProvider
from backend.services.llm.exceptions import (
    LLMAuthenticationError,
    LLMConfigurationError,
    LLMError,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseMalformedError,
    LLMTimeoutError,
    LLMValidationError,
)
from backend.services.llm.mock_provider import MockLLMProvider
from backend.services.llm.openai_provider import OpenAIProvider
from backend.services.llm.schemas import (
    LLMCodeChange,
    LLMMessage,
    LLMPatchGeneration,
    LLMResponse,
    LLMRiskAnalysis,
)
from backend.services.llm.service import LLMService

__all__ = [
    "LLMProvider",
    "OpenAIProvider",
    "MockLLMProvider",
    "LLMService",
    "LLMMessage",
    "LLMResponse",
    "LLMRiskAnalysis",
    "LLMCodeChange",
    "LLMPatchGeneration",
    "LLMError",
    "LLMConfigurationError",
    "LLMProviderUnavailableError",
    "LLMAuthenticationError",
    "LLMRateLimitError",
    "LLMTimeoutError",
    "LLMResponseMalformedError",
    "LLMValidationError",
]
