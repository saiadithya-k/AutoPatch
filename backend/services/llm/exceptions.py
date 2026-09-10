"""AutoPatch LLM Service custom exception hierarchy."""


class LLMError(Exception):
    """Base exception for all AutoPatch LLM-related errors."""
    pass


class LLMConfigurationError(LLMError):
    """Raised when LLM configuration or environment variables are missing/invalid."""
    pass


class LLMProviderUnavailableError(LLMError):
    """Raised when the target LLM provider endpoint is unreachable or returning 5xx."""
    pass


class LLMAuthenticationError(LLMError):
    """Raised when provider authentication fails (e.g., invalid/expired API key)."""
    pass


class LLMRateLimitError(LLMError):
    """Raised when the LLM provider rate limit or quota has been exceeded."""
    pass


class LLMTimeoutError(LLMError):
    """Raised when an LLM API request exceeds the configured timeout duration."""
    pass


class LLMResponseMalformedError(LLMError):
    """Raised when the LLM returns unparseable or non-JSON content when JSON is required."""
    pass


class LLMValidationError(LLMError):
    """Raised when the LLM response fails Pydantic schema validation."""
    pass
