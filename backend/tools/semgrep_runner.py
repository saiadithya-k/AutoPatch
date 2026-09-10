"""Semgrep SAST scanner runner with safe subprocess execution and structured parsing."""

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
class SemgrepResult:
    """Structured result from a Semgrep scan execution."""
    success: bool
    exit_code: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error_message: Optional[str] = None


class SemgrepRunner:
    """Safe runner wrapper for Semgrep static analysis engine."""

    def __init__(self, config: str = "p/security-audit", timeout: Optional[int] = None):
        """
        Initialize Semgrep runner.
        :param config: Semgrep ruleset configuration (default 'p/security-audit' or 'p/python' / local rule path).
        :param timeout: Execution timeout in seconds.
        """
        settings = get_settings()
        self.config = config
        self.timeout = timeout or settings.SCAN_TIMEOUT

    def _resolve_executable(self) -> list[str]:
        """
        Locate Semgrep executable safely on current system.
        Returns command array prefix.
        """
        # 1. System PATH
        which_semgrep = shutil.which("semgrep")
        if which_semgrep:
            return [which_semgrep]

        # 2. Python environment Scripts directory (common on Windows)
        scripts_semgrep = os.path.join(os.path.dirname(sys.executable), "Scripts", "semgrep.exe")
        if os.path.exists(scripts_semgrep):
            return [scripts_semgrep]

        # 3. pysemgrep.exe in Scripts directory
        scripts_pysemgrep = os.path.join(os.path.dirname(sys.executable), "Scripts", "pysemgrep.exe")
        if os.path.exists(scripts_pysemgrep):
            return [scripts_pysemgrep]

        # 4. Fallback directly to 'semgrep'
        return ["semgrep"]

    def run(self, repo_path: str | Path, custom_config: Optional[str] = None) -> SemgrepResult:
        """
        Execute Semgrep scan safely against the specified repository path.

        :param repo_path: Validated path to target repository.
        :param custom_config: Optional override for Semgrep rule config.
        :return: Structured SemgrepResult.
        """
        target_path = Path(repo_path).resolve()
        if not target_path.exists():
            return SemgrepResult(
                success=False,
                exit_code=-1,
                error_message=f"Target path does not exist: {target_path}"
            )

        cmd_base = self._resolve_executable()
        rule_config = custom_config or self.config

        # Build safe subprocess argument list (no shell=True)
        cmd = cmd_base + ["--config", rule_config, "--json", "--quiet", str(target_path)]

        logger.info("Executing Semgrep: %s", " ".join(cmd))

        # Set environment variable to suppress telemetry and metrics prompts
        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"
        env["PYTHONUTF8"] = "1"

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
                env=env
            )
        except subprocess.TimeoutExpired as e:
            logger.error("Semgrep scan timed out after %s seconds", self.timeout)
            return SemgrepResult(
                success=False,
                exit_code=-1,
                stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
                stderr=e.stderr or "" if isinstance(e.stderr, str) else "",
                error_message=f"Semgrep scan timed out after {self.timeout} seconds."
            )
        except FileNotFoundError as e:
            logger.error("Semgrep executable not found: %s", e)
            return SemgrepResult(
                success=False,
                exit_code=-1,
                error_message=f"Semgrep executable not found: {e}"
            )
        except Exception as e:
            logger.error("Unexpected error executing Semgrep: %s", e)
            return SemgrepResult(
                success=False,
                exit_code=-1,
                error_message=f"Failed to execute Semgrep: {str(e)}"
            )

        stdout = process.stdout.strip()
        stderr = process.stderr.strip()
        exit_code = process.returncode

        # Semgrep returns 0 on successful scan (with or without findings)
        # Even with exit_code != 0, valid JSON might be emitted on non-fatal warnings
        if stdout:
            try:
                data = json.loads(stdout)
                findings = data.get("results", [])
                errors = data.get("errors", [])

                return SemgrepResult(
                    success=True,
                    exit_code=exit_code,
                    findings=findings,
                    errors=errors,
                    stdout=stdout,
                    stderr=stderr
                )
            except json.JSONDecodeError:
                # If exit code was 0 but not JSON, report error
                pass

        if exit_code == 0:
            return SemgrepResult(
                success=True,
                exit_code=0,
                findings=[],
                errors=[],
                stdout=stdout,
                stderr=stderr
            )

        return SemgrepResult(
            success=False,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error_message=f"Semgrep exited with code {exit_code}: {stderr or stdout}"
        )
