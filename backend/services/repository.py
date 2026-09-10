"""Repository validation and filesystem inspection service."""

import os
from pathlib import Path
from typing import Optional


class RepositoryValidationError(Exception):
    """Exception raised when repository path validation fails."""
    pass


class RepositoryService:
    """Service responsible for validating repository paths safely and ensuring read-only access."""

    def __init__(self, allowed_base_dir: Optional[str] = None):
        """
        Initialize repository service.
        :param allowed_base_dir: Optional root directory restriction for path traversal protection.
        """
        self.allowed_base_dir = Path(allowed_base_dir).resolve() if allowed_base_dir else None

    def validate_repository_path(self, repo_path: str) -> Path:
        """
        Validate and resolve a repository path.

        Ensures:
        - Path is not empty.
        - Path is resolved to absolute canonical representation.
        - Path exists on filesystem.
        - Path points to a directory.
        - Path does not escape allowed base directory (if configured).

        :param repo_path: Target filesystem path to repository.
        :return: Resolved Path instance.
        :raises RepositoryValidationError: If validation checks fail.
        """
        if not repo_path or not repo_path.strip():
            raise RepositoryValidationError("Repository path cannot be empty.")

        try:
            resolved_path = Path(repo_path).resolve()
        except Exception as e:
            raise RepositoryValidationError(f"Invalid path format '{repo_path}': {e}") from e

        if not resolved_path.exists():
            raise RepositoryValidationError(f"Repository path does not exist: {resolved_path}")

        if not resolved_path.is_dir():
            raise RepositoryValidationError(f"Repository path is not a directory: {resolved_path}")

        if self.allowed_base_dir:
            try:
                resolved_path.relative_to(self.allowed_base_dir)
            except ValueError:
                raise RepositoryValidationError(
                    f"Access denied: Path '{resolved_path}' is outside allowed base '{self.allowed_base_dir}'."
                )

        return resolved_path

    def get_python_files(self, repo_path: str) -> list[Path]:
        """
        List all Python (.py) files inside a validated repository path.
        :param repo_path: Validated repository path.
        :return: List of Path objects for Python files.
        """
        validated_dir = self.validate_repository_path(repo_path)
        return list(validated_dir.rglob("*.py"))
