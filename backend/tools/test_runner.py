"""AutoPatch Dedicated Test Runner Tool.

Executes project test suites in an isolated temporary workspace using controlled,
hardcoded subprocess argument lists with timeouts, output capture, and zero shell=True.
Can execute via SandboxExecutor (Docker or local workspace) or direct subprocess fallback.
Accurately reports passed, failed, skipped, collection errors, and total scheduled tests.
"""

import logging
import re
import sys
import time
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

from backend.config import get_settings
from backend.tools.sandbox import SandboxExecutor, get_default_sandbox_executor

logger = logging.getLogger(__name__)


class TestResult(BaseModel):
    """Structured result of test execution."""
    __test__ = False

    success: bool = Field(description="True if test process exited with code 0 and no test or collection errors occurred")
    exit_code: int = Field(description="Process exit code")
    command: list[str] = Field(description="Controlled subprocess argument list executed")
    stdout: str = Field(default="", description="Captured standard output")
    stderr: str = Field(default="", description="Captured standard error")
    duration: float = Field(default=0.0, description="Test execution duration in seconds")
    timed_out: bool = Field(default=False, description="True if test process timed out")
    tests_passed: int = Field(default=0, description="Number of passed tests parsed from output")
    tests_failed: int = Field(default=0, description="Number of failed tests parsed from output")
    tests_skipped: int = Field(default=0, description="Number of skipped tests parsed from output")
    tests_total: int = Field(default=0, description="Total number of scheduled tests (passed + failed + skipped)")
    tests_run: int = Field(default=0, description="Total number of tests actually executed (passed + failed)")
    collection_errors: int = Field(default=0, description="Number of collection/configuration errors")
    collection_failed: bool = Field(default=False, description="True if pytest failed during test collection")
    error_message: Optional[str] = Field(default=None, description="Detailed error description if execution failed")


class TestRunner:
    """Dedicated test runner tool for executing tests safely within an isolated workspace or sandbox."""
    __test__ = False

    def __init__(
        self,
        timeout: Optional[int] = None,
        sandbox: Optional[SandboxExecutor] = None,
    ):
        """
        Initialize TestRunner.

        :param timeout: Execution timeout in seconds. Defaults to settings.TEST_TIMEOUT.
        :param sandbox: Optional SandboxExecutor to execute commands inside (Docker or local).
        """
        self.timeout = timeout or get_settings().TEST_TIMEOUT
        self.sandbox = sandbox or get_default_sandbox_executor()

    @classmethod
    def _parse_pytest_summary(cls, output: str) -> tuple[int, int, int]:
        """
        Extract passed, failed, and skipped test counts from pytest output.
        Returns: (passed, failed, skipped)
        """
        passed = 0
        failed = 0
        skipped = 0

        m_passed = re.search(r"(\d+)\s+passed", output)
        if m_passed:
            passed = int(m_passed.group(1))

        m_failed = re.search(r"(\d+)\s+failed", output)
        if m_failed:
            failed = int(m_failed.group(1))

        m_skipped = re.search(r"(\d+)\s+skipped", output)
        if m_skipped:
            skipped = int(m_skipped.group(1))

        m_errors = re.search(r"(\d+)\s+error", output)
        if m_errors:
            failed += int(m_errors.group(1))

        return passed, failed, skipped

    @classmethod
    def _parse_pytest_collection_status(cls, output: str, exit_code: int) -> tuple[int, bool]:
        """
        Extract collection error count and determine if pytest failed during collection.
        Returns: (collection_errors, collection_failed)
        """
        collection_errors = 0
        collection_failed = False

        m_errors = re.search(r"(\d+)\s+error", output)
        if m_errors:
            collection_errors = int(m_errors.group(1))

        # Check for pytest collection error patterns or exit code 2 (pytest interrupted / collection error)
        if exit_code == 2 or collection_errors > 0 or re.search(r"(?:collection failed|error during collection|=== ERRORS ===)", output, re.IGNORECASE):
            collection_failed = True
            if collection_errors == 0 and exit_code != 0:
                collection_errors = 1

        return collection_errors, collection_failed

    def run_tests(
        self,
        workspace_path: Path | str,
        test_files: Optional[list[str]] = None,
    ) -> TestResult:
        """
        Execute pytest in the given workspace using controlled arguments.
        Never executes arbitrary shell commands. Never uses shell=True.

        :param workspace_path: Root of the isolated temporary workspace.
        :param test_files: Optional relative paths to specific test files to run.
        :return: TestResult model.
        """
        workspace_path = Path(workspace_path).resolve()
        if not workspace_path.exists() or not workspace_path.is_dir():
            return TestResult(
                success=False,
                exit_code=-1,
                command=[],
                duration=0.0,
                error_message=f"Workspace path '{workspace_path}' does not exist.",
            )

        # In Docker containers, 'python' is in PATH. On host, sys.executable is used.
        if self.sandbox and self.sandbox.sandbox_type == "docker":
            cmd = ["python", "-m", "pytest", "-q"]
        else:
            cmd = [sys.executable, "-m", "pytest", "-q"]

        if test_files:
            for tf in test_files:
                norm = tf.replace("\\", "/").strip()
                # Ensure test file path is relative and stays within workspace
                if ".." in norm.split("/") or norm.startswith("/"):
                    logger.warning("Unsafe test file path '%s' skipped.", tf)
                    continue

                target_test = workspace_path / norm
                if target_test.exists():
                    cmd.append(norm)

        start_time = time.perf_counter()
        logger.info(
            "Running tests in %s via %s: %s (timeout: %ds)",
            workspace_path,
            self.sandbox.sandbox_type if self.sandbox else "local",
            " ".join(cmd),
            self.timeout,
        )

        exec_res = self.sandbox.run_command(cmd, cwd=workspace_path, timeout=self.timeout)
        duration = exec_res.duration if exec_res.duration > 0 else (time.perf_counter() - start_time)

        # Parse test metrics from output
        combined_output = (exec_res.stdout or "") + "\n" + (exec_res.stderr or "")
        passed, failed, skipped = self._parse_pytest_summary(combined_output)
        coll_errors, coll_failed = self._parse_pytest_collection_status(combined_output, exec_res.exit_code)

        tests_total = passed + failed + skipped
        tests_run = passed + failed

        # Success requires exit code 0, no timeout, no collection failure, and no failed tests
        success = (exec_res.exit_code == 0 and not exec_res.timed_out and not coll_failed and failed == 0 and passed > 0)

        err_msg = None
        if not success:
            if exec_res.timed_out:
                err_msg = f"Test execution timed out after {self.timeout}s."
            elif coll_failed:
                err_msg = f"Pytest collection failed ({coll_errors} collection error(s))."
            elif failed > 0:
                err_msg = f"{failed} test(s) failed with exit code {exec_res.exit_code}."
            elif exec_res.exit_code != 0:
                err_msg = f"Tests failed with exit code {exec_res.exit_code}."
            else:
                err_msg = "No tests executed successfully; validation requires at least one passing test."

        return TestResult(
            success=success,
            exit_code=exec_res.exit_code,
            command=cmd,
            stdout=exec_res.stdout,
            stderr=exec_res.stderr,
            duration=round(duration, 3),
            timed_out=exec_res.timed_out,
            tests_passed=passed,
            tests_failed=failed,
            tests_skipped=skipped,
            tests_total=tests_total,
            tests_run=tests_run,
            collection_errors=coll_errors,
            collection_failed=coll_failed,
            error_message=err_msg,
        )
