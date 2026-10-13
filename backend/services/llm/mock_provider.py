"""Mock LLM Provider for isolated, offline testing without network or API keys."""

import json
from typing import Any, Callable, Optional, Type, TypeVar
from pydantic import BaseModel, ValidationError

from backend.services.llm.base import LLMProvider
from backend.services.llm.exceptions import (
    LLMAuthenticationError,
    LLMProviderUnavailableError,
    LLMRateLimitError,
    LLMResponseMalformedError,
    LLMTimeoutError,
    LLMValidationError,
)
from backend.services.llm.schemas import LLMMessage, LLMResponse

T = TypeVar("T")


class MockLLMProvider(LLMProvider):
    """Mock LLM provider for unit tests and local simulation."""

    def __init__(
        self,
        model: str = "mock-model-v1",
        canned_content: Optional[str] = None,
        canned_parsed: Optional[Any] = None,
        response_generator: Optional[Callable[[list[LLMMessage]], str]] = None,
        raise_auth_error: bool = False,
        raise_timeout: bool = False,
        raise_rate_limit: bool = False,
        raise_unavailable: bool = False,
        raise_malformed: bool = False,
        raise_validation: bool = False,
    ):
        self._model = model
        self.canned_content = canned_content
        self.canned_parsed = canned_parsed
        self.response_generator = response_generator
        self.raise_auth_error = raise_auth_error
        self.raise_timeout = raise_timeout
        self.raise_rate_limit = raise_rate_limit
        self.raise_unavailable = raise_unavailable
        self.raise_malformed = raise_malformed
        self.raise_validation = raise_validation
        self.call_history: list[list[LLMMessage]] = []

    @property
    def name(self) -> str:
        return "mock"

    @property
    def model(self) -> str:
        return self._model

    def generate(
        self,
        messages: list[LLMMessage],
        response_schema: Optional[Type[T]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> LLMResponse:
        """Simulate LLM generation according to configured test behavior."""
        self.call_history.append(messages)

        if self.raise_auth_error:
            raise LLMAuthenticationError("Mock: Invalid API key")
        if self.raise_timeout:
            raise LLMTimeoutError("Mock: Request timed out")
        if self.raise_rate_limit:
            raise LLMRateLimitError("Mock: Rate limit exceeded")
        if self.raise_unavailable:
            raise LLMProviderUnavailableError("Mock: Provider unavailable")
        if self.raise_malformed:
            raise LLMResponseMalformedError("Mock: Response was not valid JSON")

        if self.raise_validation and response_schema:
            raise LLMValidationError(f"Mock: Validation failed for schema {response_schema.__name__}")

        if self.response_generator:
            content = self.response_generator(messages)
        elif self.canned_content is not None:
            content = self.canned_content
        elif self.canned_parsed is not None:
            if isinstance(self.canned_parsed, BaseModel):
                content = self.canned_parsed.model_dump_json()
            elif isinstance(self.canned_parsed, dict):
                content = json.dumps(self.canned_parsed)
            else:
                content = str(self.canned_parsed)
        elif response_schema is not None:
            # Generate minimal valid dummy payload for common schemas
            if response_schema.__name__ == "LLMPatchGeneration":
                content = json.dumps({
                    "explanation": "Mock patch replacing insecure call with safe alternative",
                    "changes": [
                        {
                            "file_path": "app.py",
                            "start_line": 14,
                            "end_line": 14,
                            "original_code": "    return os.system(command)",
                            "replacement_code": "    import shlex\n    return subprocess.run(shlex.split(command), check=True).returncode",
                        }
                    ],
                    "unified_diff": "",
                    "assumptions": ["subprocess and shlex available in stdlib"],
                    "tests_to_run": ["test_execute_system_diagnostic"],
                })
            else:
                content = json.dumps({
                    "summary": "Mock summary of security finding",
                    "attack_vector": "Mock attack vector demonstration",
                    "impact_analysis": "Mock impact analysis",
                    "mitigation_guidance": "Mock remediation steps",
                    "confidence_assessment": "High confidence true positive",
                })
        else:
            content = "Mock LLM text completion response."

        parsed_obj: Optional[Any] = None
        if response_schema is not None:
            try:
                parsed_json = json.loads(content)
                parsed_obj = response_schema.model_validate(parsed_json)
            except json.JSONDecodeError as e:
                raise LLMResponseMalformedError(f"Mock output JSON decode failed: {e}") from e
            except ValidationError as e:
                raise LLMValidationError(f"Mock output validation failed: {e}") from e

        return LLMResponse(
            content=content,
            parsed=parsed_obj,
            model=self._model,
            usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
            raw_response={"mock": True},
        )
