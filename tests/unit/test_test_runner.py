"""Unit tests for dedicated TestRunner tool.

Verifies test execution, output capture, exit codes, metric extraction,
timeouts, and strict shell=False guarantees.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import subprocess
import pytest

from backend.tools.test_runner import TestResult, TestRunner


def test_test_runner_successful_execution(tmp_path: Path):
    """Verify clean test run with 0 exit code, passed tests, and output capture."""
    test_file = tmp_path / "test_sample.py"
    test_file.write_text("def test_ok(): assert True\n", encoding="utf-8")

    runner = TestRunner(timeout=30)
    result = runner.run_tests(workspace_path=tmp_path)

    assert result.success is True
    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.tests_passed >= 1
    assert result.tests_failed == 0
    assert result.error_message is None
    assert "pytest" in result.command[2]


def test_test_runner_failing_tests(tmp_path: Path):
    """Verify failing tests are caught with non-zero exit code and failure counts."""
    test_file = tmp_path / "test_fail.py"
    test_file.write_text("def test_fail(): assert False\n", encoding="utf-8")

    runner = TestRunner(timeout=30)
    result = runner.run_tests(workspace_path=tmp_path)

    assert result.success is False
    assert result.exit_code != 0
    assert result.timed_out is False
    assert result.tests_failed >= 1
    assert "failed" in result.error_message.lower()


def test_test_runner_timeout_handling(tmp_path: Path):
    """Verify timeout expiration results in timed_out=True and success=False."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["pytest"], timeout=5)):
        runner = TestRunner(timeout=5)
        result = runner.run_tests(workspace_path=tmp_path)

        assert result.success is False
        assert result.timed_out is True
        assert "timed out" in result.stderr.lower()


def test_test_runner_missing_workspace(tmp_path: Path):
    """Verify non-existent workspace path fails safely."""
    missing = tmp_path / "does_not_exist"
    runner = TestRunner(timeout=10)
    result = runner.run_tests(workspace_path=missing)

    assert result.success is False
    assert result.exit_code == -1
    assert "does not exist" in result.error_message.lower()


def test_test_runner_strictly_shell_false(tmp_path: Path):
    """Verify that subprocess.run is NEVER called with shell=True."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="1 passed in 0.01s", stderr="")

        runner = TestRunner(timeout=15)
        runner.run_tests(workspace_path=tmp_path)

        assert mock_run.called
        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("shell") is False, "CRITICAL: shell must be False!"


def test_test_runner_output_metric_parsing():
    """Verify regex metric parsing from various pytest summary string formats."""
    runner = TestRunner()

    p1, f1, s1 = runner._parse_pytest_summary("10 passed in 0.45s")
    assert p1 == 10 and f1 == 0 and s1 == 0

    p2, f2, s2 = runner._parse_pytest_summary("2 failed, 8 passed, 1 skipped in 1.20s")
    assert p2 == 8 and f2 == 2 and s2 == 1

    p3, f3, s3 = runner._parse_pytest_summary("1 error during collection")
    assert f3 == 1
