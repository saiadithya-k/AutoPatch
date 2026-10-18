"""AutoPatch Temporary Workspace Manager.

Provides isolated workspace copies of repositories for safe patch application,
syntax validation, test execution, and security re-scanning.
Guarantees that the original repository remains 100% untouched and defends against
symlink directory breakouts, broken symlinks, circular links, and permission errors during cleanup.
"""

import logging
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Standard directories and files to exclude from workspace copy to maintain performance
DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "venv",
    ".venv",
    ".venv-runtime",
    ".test-artifacts",
    ".test-tmp",
    "env",
    "node_modules",
}


class TemporaryWorkspace:
    """
    Context manager that creates an isolated copy of a repository in a temporary directory.
    Guarantees that no operations mutate the original repository.
    Strictly verifies that symlinks do not escape the repository boundary.
    """

    def __init__(
        self,
        repository_path: str | Path,
        prefix: str = "autopatch_ws_",
        auto_cleanup: bool = True,
        container_access: bool = False,
    ):
        """
        Initialize temporary workspace manager.

        :param repository_path: Path to the validated source repository.
        :param prefix: Temporary directory prefix.
        :param auto_cleanup: Whether to delete the temporary workspace on exit.
        """
        self.source_path = Path(repository_path).resolve()
        self.prefix = prefix
        self.auto_cleanup = auto_cleanup
        self.container_access = container_access
        self.temp_dir: Optional[str] = None
        self.workspace_path: Optional[Path] = None

    def __enter__(self) -> Path:
        """Create and populate isolated workspace."""
        return self.create()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clean up isolated workspace."""
        if self.auto_cleanup:
            self.cleanup()

    def create(self) -> Path:
        """Create temporary workspace directory and safely copy repository contents."""
        if not self.source_path.exists() or not self.source_path.is_dir():
            raise ValueError(f"Source repository path '{self.source_path}' does not exist or is not a directory.")

        self.temp_dir = tempfile.mkdtemp(prefix=self.prefix)
        self.workspace_path = Path(self.temp_dir).resolve()

        # Workspace must never be inside source repository
        if self._is_within_boundary(self.workspace_path, self.source_path):
            self.cleanup()
            raise RuntimeError(f"Temporary workspace '{self.workspace_path}' cannot reside inside source repository.")

        logger.debug("Created temporary workspace at %s for source %s", self.workspace_path, self.source_path)

        try:
            self._safe_copy_repository()
            if self.container_access and os.name == "posix":
                self._prepare_container_access()
        except BaseException:
            self.cleanup()
            raise
        return self.workspace_path

    def _prepare_container_access(self) -> None:
        """Share only the disposable copy with the container's supplementary GID.

        mkdtemp creates a private 0700 directory on Linux. The non-root
        container joins the host process's group and needs group access to this
        copy. Do not chmod the source, follow symlinks, or grant world access.
        """
        for root, dirs, files in os.walk(self.workspace_path, followlinks=False):
            directory = Path(root)
            directory.chmod(stat.S_IMODE(directory.stat().st_mode) | stat.S_IRWXU | stat.S_IRWXG | stat.S_ISGID)
            dirs[:] = [name for name in dirs if not (directory / name).is_symlink()]
            for name in files:
                path = directory / name
                if not path.is_symlink():
                    path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

    def _safe_copy_repository(self) -> None:
        """
        Copy files from source repository to workspace while enforcing symlink escape guards.
        Handles source symlinks, nested symlinks, broken symlinks, and circular links safely.
        """
        source_root = self.source_path
        visited_dirs: set[Path] = set()

        for root, dirs, files in os.walk(source_root, followlinks=False):
            current_path = Path(root)

            try:
                real_current = current_path.resolve()
            except Exception:
                dirs.clear()
                continue

            if real_current in visited_dirs:
                # Prevent infinite loops in circular directory links
                dirs.clear()
                continue
            visited_dirs.add(real_current)

            rel_root = current_path.relative_to(source_root)
            dest_dir = self.workspace_path / rel_root

            # Filter out ignored directories
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORED_DIRS]

            # Directory symlink check
            if current_path.is_symlink():
                try:
                    real_target = current_path.resolve(strict=True)
                    if not self._is_within_boundary(real_target, source_root):
                        logger.warning(
                            "Directory symlink '%s' points outside repository to '%s'. Skipping.",
                            current_path,
                            real_target,
                        )
                        dirs.clear()
                        continue
                except Exception as e:
                    logger.warning("Broken directory symlink '%s' encountered: %s. Skipping.", current_path, e)
                    dirs.clear()
                    continue

            dest_dir.mkdir(parents=True, exist_ok=True)

            for fname in files:
                src_file = current_path / fname
                dest_file = dest_dir / fname

                # Symlink escape protection for files
                if src_file.is_symlink():
                    try:
                        real_target = src_file.resolve(strict=True)
                        if not self._is_within_boundary(real_target, source_root):
                            logger.warning(
                                "Symlink file '%s' resolves outside repository boundary to '%s'. Skipping.",
                                src_file,
                                real_target,
                            )
                            continue
                    except FileNotFoundError:
                        logger.warning("Broken file symlink '%s' encountered. Skipping.", src_file)
                        continue
                    except Exception as e:
                        logger.warning("Failed to resolve file symlink '%s': %s. Skipping.", src_file, e)
                        continue

                try:
                    # Regular copy preserving file content without following dangerous external links
                    shutil.copy2(src_file, dest_file, follow_symlinks=False)
                except Exception as e:
                    logger.warning("Failed to copy file '%s' to workspace: %s", src_file, e)

    @staticmethod
    def _is_within_boundary(target: Path, boundary: Path) -> bool:
        """Verify that target resides strictly within boundary directory."""
        try:
            target.resolve().relative_to(boundary.resolve())
            return True
        except ValueError:
            return False

    def cleanup(self) -> None:
        """Safely remove the temporary workspace directory, handling read-only permission errors."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            def _remove_readonly(func, path, exc_info):
                # Clear read-only attribute and retry removal
                try:
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                except Exception as e:
                    logger.warning("Failed to remove '%s' during cleanup: %s", path, e)

            try:
                shutil.rmtree(self.temp_dir, onerror=_remove_readonly)
                logger.debug("Removed temporary workspace %s", self.temp_dir)
            except Exception as e:
                logger.warning("Failed to cleanup temporary workspace %s: %s", self.temp_dir, e)
            finally:
                self.temp_dir = None
                self.workspace_path = None
