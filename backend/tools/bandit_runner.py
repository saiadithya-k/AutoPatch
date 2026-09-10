"""Bandit SAST scanner runner with safe subprocess execution and structured parsing."""

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from backend.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class BanditResult:
    """Structured result from a Bandit scan execution."""
    success: bool
    exit_code: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    error_message: Optional[str] = None


class BanditRunner:
    """Safe runner wrapper for Bandit static analysis tool."""

    def __init__(self, timeout: Optional[int] = None):
        settings = get_settings()
        self.timeout = timeout or settings.SCAN_TIMEOUT

    def _resolve_executable(self) -> list[str]:
        """
        Locate Bandit executable safely on current system.
        Returns command array prefix.
        """
        # 1. System PATH
        which_bandit = shutil.which("bandit")
        if which_bandit:
            return [which_bandit]

        # 2. Python environment Scripts directory (common on Windows)
        scripts_bandit = os.path.join(os.path.dirname(sys.executable), "Scripts", "bandit.exe")
        if os.path.exists(scripts_bandit):
            return [scripts_bandit]

        # 3. Python module execution fallback
        return [sys.executable, "-m", "bandit"]

    def run(self, repo_path: str | Path) -> BanditResult:
        """
        Execute Bandit scan safely against the specified repository path.

        :param repo_path: Validated path to target repository.
        :return: Structured BanditResult.
        """
        target_path = Path(repo_path).resolve()
        if not target_path.exists():
            return BanditResult(
                success=False,
                exit_code=-1,
                error_message=f"Target path does not exist: {target_path}"
            )

        cmd_base = self._resolve_executable()
        # Safe argument list - no shell=True, arguments properly separated
        cmd = cmd_base + ["-r", str(target_path), "-f", "json", "-q"]

        logger.info("Executing Bandit: %s", " ".join(cmd))

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False
            )
        except subprocess.TimeoutExpired as e:
            logger.error("Bandit scan timed out after %s seconds", self.timeout)
            return BanditResult(
                success=False,
                exit_code=-1,
                stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
                stderr=e.stderr or "" if isinstance(e.stderr, str) else "",
                error_message=f"Bandit scan timed out after {self.timeout} seconds."
            )
        except FileNotFoundError as e:
            logger.error("Bandit executable not found: %s", e)
            return BanditResult(
                success=False,
                exit_code=-1,
                error_message=f"Bandit executable not found: {e}"
            )
        except Exception as e:
            logger.error("Unexpected error executing Bandit: %s", e)
            return BanditResult(
                success=False,
                exit_code=-1,
                error_message=f"Failed to execute Bandit: {str(e)}"
            )

        stdout = process.stdout.strip()
        stderr = process.stderr.strip()
        exit_code = process.returncode

        # Bandit returns 0 when no issues found, 1 when issues found. Both are successful scans!
        if exit_code in (0, 1):
            try:
                data = json.loads(stdout) if stdout else {}
                findings = data.get("results", [])
                errors = data.get("errors", [])
                metrics = data.get("metrics", {})

                return BanditResult(
                    success=True,
                    exit_code=exit_code,
                    findings=findings,
                    errors=errors,
                    metrics=metrics,
                    stdout=stdout,
                    stderr=stderr
                )
            except json.JSONDecodeError as e:
                logger.error("Failed to parse Bandit JSON output: %s", e)
                return BanditResult(
                    success=False,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    error_message=f"Malformed JSON output from Bandit: {e}"
                )

        # Non-zero/non-one exit code indicates scanner crash or execution failure
        return BanditResult(
            success=False,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error_message=f"Bandit exited with error code {exit_code}: {stderr or stdout}"
        )
