"""OpenAI LLM provider implementation with structured JSON output and robust error handling."""

import json
import logging
from typing import Any, Optional, Type, TypeVar
import httpx
from pydantic import ValidationError

from backend.config import get_settings
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
from backend.services.llm.schemas import LLMMessage, LLMResponse

logger = logging.getLogger(__name__)

T = TypeVar("T")


class OpenAIProvider(LLMProvider):
    """OpenAI API provider for chat completions and structured output."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        timeout: Optional[float] = None,
    ):
        """
        Initialize OpenAI provider.

        :param api_key: OpenAI API key. If omitted, loaded securely from settings/env.
        :param model: Target model identifier (default from settings: 'gpt-4o').
        :param base_url: OpenAI API endpoint base URL.
        :param timeout: Request timeout in seconds.
        """
        settings = get_settings()
        self._api_key = api_key or settings.OPENAI_API_KEY
        self._model = model or settings.LLM_MODEL or "gpt-4o"
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout if timeout is not None else settings.LLM_TIMEOUT

    @property
    def name(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    def _ensure_configured(self) -> None:
        """Validate that the API key is present and not empty."""
        if not self._api_key or not self._api_key.strip():
            raise LLMConfigurationError(
                "OpenAI API key is not configured. Set OPENAI_API_KEY environment variable."
            )

    def _prepare_payload(
        self,
        messages: list[LLMMessage],
        response_schema: Optional[Type[T]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
    ) -> dict[str, Any]:
        """Construct safe request payload for OpenAI chat completion endpoint."""
        formatted_messages = [
            {"role": m.role, "content": m.content} for m in messages
        ]

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": formatted_messages,
            "temperature": temperature,
        }

        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        # If structured schema is requested, request JSON output format
        if response_schema is not None:
            payload["response_format"] = {"type": "json_object"}

        return payload

    def generate(
        self,
        messages: list[LLMMessage],
        response_schema: Optional[Type[T]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        """
        Send chat completion request to OpenAI with structured validation and error handling.
        """
        self._ensure_configured()

        payload = self._prepare_payload(
            messages=messages,
            response_schema=response_schema,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        req_timeout = timeout or self._timeout
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        logger.info(
            "Dispatching LLM request to OpenAI (model=%s, messages_count=%d)",
            self._model,
            len(messages),
        )

        try:
            with httpx.Client(timeout=req_timeout) as client:
                response = client.post(url, json=payload, headers=headers)
        except httpx.TimeoutException as e:
            logger.error("OpenAI request timed out after %.1fs: %s", req_timeout, e)
            raise LLMTimeoutError(f"OpenAI API request timed out after {req_timeout}s.") from e
        except httpx.ConnectError as e:
            logger.error("Failed to connect to OpenAI endpoint: %s", e)
            raise LLMProviderUnavailableError(f"Cannot connect to OpenAI service at {self._base_url}: {e}") from e
        except httpx.RequestError as e:
            logger.error("Network error during OpenAI request: %s", e)
            raise LLMProviderUnavailableError(f"Network error communicating with OpenAI: {e}") from e

        # Handle HTTP status codes
        if response.status_code == 401 or response.status_code == 403:
            logger.error("OpenAI authentication failed (HTTP %d)", response.status_code)
            raise LLMAuthenticationError(
                f"OpenAI authentication failed (HTTP {response.status_code}). Check OPENAI_API_KEY."
            )
        elif response.status_code == 429:
            logger.error("OpenAI rate limit / quota exceeded")
            raise LLMRateLimitError("OpenAI rate limit or quota exceeded.")
        elif response.status_code >= 500:
            logger.error("OpenAI server error (HTTP %d)", response.status_code)
            raise LLMProviderUnavailableError(
                f"OpenAI server returned error {response.status_code}: {response.text[:200]}"
            )
        elif response.status_code != 200:
            logger.error("OpenAI unexpected HTTP error: %d - %s", response.status_code, response.text[:200])
            raise LLMError(f"OpenAI returned unexpected status {response.status_code}: {response.text[:200]}")

        # Parse JSON response body
        try:
            res_data = response.json()
        except Exception as e:
            raise LLMResponseMalformedError(f"Failed to parse OpenAI response body as JSON: {e}") from e

        choices = res_data.get("choices", [])
        if not choices:
            raise LLMResponseMalformedError("OpenAI response contains empty choices list.")

        content = choices[0].get("message", {}).get("content", "")
        usage = res_data.get("usage", {})
        parsed_model_obj: Optional[Any] = None

        # Validate against response schema if requested
        if response_schema is not None:
            try:
                parsed_json = json.loads(content)
            except json.JSONDecodeError as e:
                logger.error("Model output was not valid JSON: %s", e)
                raise LLMResponseMalformedError(
                    f"Model output could not be decoded as JSON: {e}. Output was: {content[:200]}"
                ) from e

            try:
                parsed_model_obj = response_schema.model_validate(parsed_json)
            except ValidationError as e:
                logger.error("Model output failed schema validation for %s: %s", response_schema.__name__, e)
                raise LLMValidationError(
                    f"Model output does not match expected schema {response_schema.__name__}: {e}"
                ) from e

        return LLMResponse(
            content=content,
            parsed=parsed_model_obj,
            model=res_data.get("model", self._model),
            usage=usage,
            raw_response=res_data,
        )
