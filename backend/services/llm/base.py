"""Abstract Base Provider interface for AutoPatch LLM services."""

from abc import ABC, abstractmethod
from typing import Any, Optional, Type, TypeVar

from backend.services.llm.schemas import LLMMessage, LLMResponse

T = TypeVar("T")


class LLMProvider(ABC):
    """Abstract interface for pluggable, provider-independent LLM integrations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier name (e.g. 'openai', 'anthropic', 'mock')."""
        pass

    @property
    @abstractmethod
    def model(self) -> str:
        """Active model identifier (e.g. 'gpt-4o', 'claude-3-5-sonnet')."""
        pass

    @abstractmethod
    def generate(
        self,
        messages: list[LLMMessage],
        response_schema: Optional[Type[T]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        """
        Execute chat completion with given message history and optional structured schema.

        :param messages: List of LLMMessage instances.
        :param response_schema: Optional Pydantic model class for structured output validation.
        :param temperature: Sampling temperature (default 0.0 for deterministic outputs).
        :param max_tokens: Optional maximum tokens to generate.
        :param timeout: Optional per-request timeout in seconds.
        :return: LLMResponse containing raw text, token usage, and validated Pydantic model in `parsed`.
        :raises LLMError: On provider failure, timeout, auth error, or schema validation failure.
        """
        pass

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        response_schema: Optional[Type[T]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        """
        Convenience wrapper for generating a response from a prompt string and optional system prompt.

        :param prompt: User prompt or contextual instructions.
        :param system_prompt: Optional system-level role guidance.
        :param response_schema: Optional Pydantic model class for structured output.
        :param temperature: Sampling temperature.
        :param max_tokens: Maximum tokens to generate.
        :param timeout: Request timeout in seconds.
        :return: LLMResponse with output and validated schema in `parsed`.
        """
        messages: list[LLMMessage] = []
        if system_prompt:
            messages.append(LLMMessage(role="system", content=system_prompt))
        messages.append(LLMMessage(role="user", content=prompt))

        return self.generate(
            messages=messages,
            response_schema=response_schema,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )
