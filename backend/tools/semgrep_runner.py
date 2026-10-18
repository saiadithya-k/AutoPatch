"""Semgrep SAST scanner runner with safe subprocess execution and structured parsing."""

import json
import hashlib
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from backend.config import get_settings
from backend.tools.sandbox import SandboxExecutor

LOCAL_RULES = Path(__file__).with_name("semgrep_rules") / "python-security.yaml"
RULESET_VERSION = "autopatch-python-security-v1"

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

    def __init__(self, config: Optional[str] = None, timeout: Optional[int] = None,
                 sandbox: Optional[SandboxExecutor] = None):
        """
        Initialize Semgrep runner.
        :param config: Semgrep ruleset configuration (default 'p/security-audit' or 'p/python' / local rule path).
        :param timeout: Execution timeout in seconds.
        """
        settings = get_settings()
        self.config = config or str(LOCAL_RULES)
        self.timeout = timeout or settings.SCAN_TIMEOUT
        self.sandbox = sandbox
        self.ruleset_provenance = {
            "version": RULESET_VERSION if self.config == str(LOCAL_RULES) else "custom",
            "sha256": hashlib.sha256(Path(self.config).read_bytes()).hexdigest() if Path(self.config).is_file() else None,
        }

    def _resolve_executable(self) -> list[str]:
        """
        Locate Semgrep executable safely on current system.
        Returns command array prefix.
        """
        # Python CLI avoids the native CLI's certificate-store startup failures on Windows.
        if os.name == "nt":
            pysemgrep = Path(sys.executable).with_name("pysemgrep.exe")
            if pysemgrep.is_file():
                return [str(pysemgrep)]
        # 1. System PATH
        which_semgrep = shutil.which("semgrep")
        if which_semgrep:
            return [which_semgrep]

        # 2. Virtualenv or direct python directory (e.g. .venv/Scripts/semgrep.exe)
        exe_name = "semgrep.exe" if os.name == "nt" else "semgrep"
        direct_semgrep = os.path.join(os.path.dirname(sys.executable), exe_name)
        if os.path.exists(direct_semgrep):
            return [direct_semgrep]

        pysemgrep_name = "pysemgrep.exe" if os.name == "nt" else "pysemgrep"
        direct_pysemgrep = os.path.join(os.path.dirname(sys.executable), pysemgrep_name)
        if os.path.exists(direct_pysemgrep):
            return [direct_pysemgrep]

        # 3. Python environment Scripts directory (common on Windows without venv)
        scripts_semgrep = os.path.join(os.path.dirname(sys.executable), "Scripts", exe_name)
        if os.path.exists(scripts_semgrep):
            return [scripts_semgrep]

        scripts_pysemgrep = os.path.join(os.path.dirname(sys.executable), "Scripts", pysemgrep_name)
        if os.path.exists(scripts_pysemgrep):
            return [scripts_pysemgrep]

        # 4. Fallback to python module execution or direct command
        return [sys.executable, "-m", "semgrep.console_scripts.pysemgrep"]

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

        docker = self.sandbox is not None and self.sandbox.sandbox_type == "docker"
        cmd_base = ["pysemgrep"] if docker else self._resolve_executable()
        rule_config = custom_config or self.config
        if docker:
            if rule_config != str(LOCAL_RULES):
                return SemgrepResult(success=False, exit_code=-1,
                    error_message="Docker validation requires the bundled offline ruleset.")
            rule_config = "/opt/autopatch/rules/python-security.yaml"

        # Build safe subprocess argument list (no shell=True)
        cmd = cmd_base + ["--config", rule_config, "--no-git-ignore", "--project-root", ".", "--json", "--quiet",
                          "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--jobs", "1"]
        for excluded in (".venv", ".venv-runtime", "venv", "node_modules", ".test-artifacts", ".test-tmp"):
            cmd.extend(["--exclude", excluded])
        cmd.append(".")

        logger.info("Executing Semgrep: %s", " ".join(cmd))

        # Set environment variable to suppress telemetry and metrics prompts
        env = os.environ.copy()
        env["SEMGREP_SEND_METRICS"] = "off"
        env["PYTHONUTF8"] = "1"

        try:
            if self.sandbox is not None:
                execution = self.sandbox.run_command(cmd, cwd=target_path, timeout=self.timeout)
                if execution.timed_out:
                    return SemgrepResult(success=False, exit_code=-1, stdout=execution.stdout,
                                         stderr=execution.stderr, error_message="Semgrep scan timed out.")
                process = subprocess.CompletedProcess(cmd, execution.exit_code, execution.stdout, execution.stderr)
            else:
                process = subprocess.run(
                cmd,
                cwd=str(target_path),
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
                if not isinstance(data, dict) or not isinstance(data.get("results"), list) or not isinstance(data.get("errors", []), list):
                    raise ValueError("Missing or malformed Semgrep result fields")
                findings = data.get("results", [])
                errors = data.get("errors", [])

                return SemgrepResult(
                    success=exit_code == 0 and not errors,
                    exit_code=exit_code,
                    findings=findings,
                    errors=errors,
                    stdout=stdout,
                    stderr=stderr,
                    error_message="Semgrep coverage is incomplete or execution failed." if exit_code != 0 or errors else None,
                )
            except (json.JSONDecodeError, ValueError, TypeError):
                # If exit code was 0 but not JSON, report error
                pass

        return SemgrepResult(
            success=False,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error_message=f"Semgrep exited with code {exit_code}: {stderr or stdout}"
        )
