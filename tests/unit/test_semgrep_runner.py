"""Unit tests for SemgrepRunner."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from backend.tools.semgrep_runner import LOCAL_RULES, SemgrepResult, SemgrepRunner


def test_semgrep_runner_nonexistent_path():
    runner = SemgrepRunner()
    result = runner.run(Path("non_existent_path_xyz"))
    assert not result.success
    assert result.exit_code == -1
    assert "does not exist" in (result.error_message or "")


def test_semgrep_runner_successful_execution(vulnerable_repo_path: Path):
    runner = SemgrepRunner()
    result = runner.run(vulnerable_repo_path)
    assert result.success is True
    assert result.exit_code == 0
    assert len(result.findings) >= 1

    first = result.findings[0]
    assert "check_id" in first
    assert "path" in first
    assert "start" in first
    assert "extra" in first


def test_semgrep_runner_timeout_handling(tmp_path: Path):
    runner = SemgrepRunner(timeout=1)
    with patch("subprocess.run", side_effect=Exception("Subprocess timeout")):
        result = runner.run(tmp_path)
        assert result.success is False
        assert "Failed to execute Semgrep" in (result.error_message or "")


def test_semgrep_runner_custom_config(vulnerable_repo_path: Path):
    runner = SemgrepRunner()
    result = runner.run(vulnerable_repo_path, custom_config=str(LOCAL_RULES))
    assert result.success is True


def test_semgrep_runner_executable_not_found(tmp_path: Path):
    runner = SemgrepRunner()
    with patch("subprocess.run", side_effect=FileNotFoundError("semgrep not found")):
        result = runner.run(tmp_path)
        assert result.success is False
        assert result.exit_code == -1
        assert "executable not found" in (result.error_message or "")


def test_semgrep_runner_zero_findings_success(tmp_path: Path):
    runner = SemgrepRunner()
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = json.dumps({"results": [], "errors": []})
    mock_process.stderr = ""

    with patch("subprocess.run", return_value=mock_process):
        result = runner.run(tmp_path)
        assert result.success is True
        assert result.exit_code == 0
        assert len(result.findings) == 0
        assert result.error_message is None
