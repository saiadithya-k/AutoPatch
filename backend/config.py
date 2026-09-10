"""AutoPatch centralized configuration module."""

import os
from functools import lru_cache
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Core Application
    APP_NAME: str = Field(default="AutoPatch", description="Application name")
    ENVIRONMENT: str = Field(default="development", description="Runtime environment")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")

    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./autopatch.db",
        description="SQLAlchemy database connection URL"
    )

    # Tool Execution & Timeouts
    SCAN_TIMEOUT: int = Field(default=120, description="Scanner timeout in seconds")
    TEST_TIMEOUT: int = Field(default=60, description="Test runner timeout in seconds")
    MAX_PATCH_RETRIES: int = Field(default=3, description="Maximum patch retry attempts")
    DOCKER_ENABLED: bool = Field(default=False, description="Whether Docker isolation is enabled")
    DOCKER_IMAGE: str = Field(default="autopatch-validator:latest", description="Docker image tag for validation sandbox")
    DOCKER_MEMORY_LIMIT: str = Field(default="512m", description="Container memory limit (e.g. 512m)")
    DOCKER_CPU_LIMIT: str = Field(default="1.0", description="Container CPU limit (e.g. 1.0)")
    DOCKER_PIDS_LIMIT: int = Field(default=100, description="Container maximum PID/process limit")
    DOCKER_TIMEOUT: int = Field(default=60, description="Docker execution timeout in seconds")
    ALLOW_LOCAL_FALLBACK: bool = Field(default=True, description="Allow local workspace fallback in development when DOCKER_ENABLED=False")

    # Repository Context Configuration
    CONTEXT_LINES_BEFORE: int = Field(default=50, description="Lines of code before vulnerability to include")
    CONTEXT_LINES_AFTER: int = Field(default=50, description="Lines of code after vulnerability to include")
    MAX_CONTEXT_FILE_SIZE: int = Field(default=1048576, description="Maximum file size in bytes to read for context (1MB)")
    MAX_CONTEXT_FILES: int = Field(default=5, description="Maximum number of related context files to include")
    MAX_CONTEXT_LINES: int = Field(default=500, description="Maximum lines of context code")

    # Patch Generation Configuration
    MAX_PATCH_FILES: int = Field(default=3, description="Maximum number of files a patch can modify")
    MAX_PATCH_LINES: int = Field(default=200, description="Maximum lines in a candidate unified diff")
    MAX_PATCH_CHARS: int = Field(default=20000, description="Maximum characters in a candidate unified diff")

    # LLM Settings (for future phases)
    LLM_PROVIDER: str = Field(default="openai", description="LLM provider name")
    LLM_MODEL: str = Field(default="gpt-4o", description="LLM model identifier")
    OPENAI_API_KEY: Optional[str] = Field(default=None, description="OpenAI API key")
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, description="Anthropic API key")


@lru_cache()
def get_settings() -> Settings:
    """Return a cached instance of application settings."""
    return Settings()
