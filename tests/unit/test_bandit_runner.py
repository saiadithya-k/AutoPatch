"""Unit tests for BanditRunner."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from backend.tools.bandit_runner import BanditResult, BanditRunner


def test_bandit_runner_nonexistent_path():
    runner = BanditRunner()
    result = runner.run(Path("non_existent_path_xyz"))
    assert not result.success
    assert result.exit_code == -1
    assert "does not exist" in (result.error_message or "")


def test_bandit_runner_successful_execution(vulnerable_repo_path: Path):
    runner = BanditRunner()
    result = runner.run(vulnerable_repo_path)
    assert result.success is True
    assert result.exit_code in (0, 1)
    assert len(result.findings) > 0

    # Ensure findings have standard keys
    first = result.findings[0]
    assert "test_id" in first
    assert "issue_text" in first
    assert "issue_severity" in first


def test_bandit_runner_timeout_handling(tmp_path: Path):
    runner = BanditRunner(timeout=1)
    with patch("subprocess.run", side_effect=Exception("Subprocess timeout")):
        result = runner.run(tmp_path)
        assert result.success is False
        assert "Failed to execute Bandit" in (result.error_message or "")


def test_bandit_runner_malformed_json_handling(tmp_path: Path):
    runner = BanditRunner()
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "{ invalid_json ]"
    mock_process.stderr = ""

    with patch("subprocess.run", return_value=mock_process):
        result = runner.run(tmp_path)
        assert result.success is False
        assert "Malformed JSON" in (result.error_message or "")


def test_bandit_runner_executable_not_found(tmp_path: Path):
    runner = BanditRunner()
    with patch("subprocess.run", side_effect=FileNotFoundError("bandit not found")):
        result = runner.run(tmp_path)
        assert result.success is False
        assert result.exit_code == -1
        assert "executable not found" in (result.error_message or "")


def test_bandit_runner_zero_findings_success(tmp_path: Path):
    runner = BanditRunner()
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = json.dumps({"results": [], "errors": [], "metrics": {}})
    mock_process.stderr = ""

    with patch("subprocess.run", return_value=mock_process):
        result = runner.run(tmp_path)
        assert result.success is True
        assert result.exit_code == 0
        assert len(result.findings) == 0
        assert result.error_message is None
