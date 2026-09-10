"""Unit tests for ScanningAgent coordination and error resilience."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from backend.agents.scanning_agent import ScanningAgent
from backend.models.vulnerability import Severity, VulnerabilityFinding
from backend.services.repository import RepositoryValidationError
from backend.tools.bandit_runner import BanditResult
from backend.tools.semgrep_runner import SemgrepResult


def test_scanning_agent_invalid_path():
    agent = ScanningAgent()
    with pytest.raises(RepositoryValidationError):
        agent.scan("invalid_repo_dir_that_does_not_exist", persist=False)


def test_scanning_agent_with_mocked_runners(tmp_path: Path):
    mock_bandit = MagicMock()
    mock_bandit.run.return_value = BanditResult(
        success=True,
        exit_code=1,
        findings=[
            {
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "issue_text": "Possible SQL injection",
                "issue_severity": "HIGH",
                "filename": str(tmp_path / "db.py"),
                "line_number": 10,
            }
        ],
    )

    mock_semgrep = MagicMock()
    mock_semgrep.run.return_value = SemgrepResult(
        success=True,
        exit_code=0,
        findings=[],
    )

    agent = ScanningAgent(
        bandit_runner=mock_bandit,
        semgrep_runner=mock_semgrep
    )

    findings, meta = agent.scan(tmp_path, persist=False)
    assert len(findings) == 1
    assert findings[0].rule_id == "B608"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == "db.py"
    assert meta["bandit"]["success"] is True


def test_scanning_agent_graceful_degradation_on_one_runner_failure(tmp_path: Path):
    """When Bandit fails, Semgrep findings are still normalized and returned."""
    mock_bandit = MagicMock()
    mock_bandit.run.return_value = BanditResult(
        success=False,
        exit_code=-1,
        error_message="Bandit crashed",
    )

    mock_semgrep = MagicMock()
    mock_semgrep.run.return_value = SemgrepResult(
        success=True,
        exit_code=0,
        findings=[
            {
                "check_id": "python.command-injection",
                "path": str(tmp_path / "server.py"),
                "start": {"line": 15},
                "end": {"line": 15},
                "extra": {
                    "message": "Command injection detected",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-78"]},
                    "lines": "os.system(cmd)",
                },
            }
        ],
    )

    agent = ScanningAgent(
        bandit_runner=mock_bandit,
        semgrep_runner=mock_semgrep
    )

    findings, meta = agent.scan(tmp_path, persist=False)
    assert len(findings) == 1
    assert findings[0].rule_id == "python.command-injection"
    assert findings[0].tool == "semgrep"
    assert len(meta["errors"]) == 1
    assert meta["scan_status"] == "DEGRADED"


def test_scanning_agent_both_runners_fail(tmp_path: Path):
    """When both Bandit and Semgrep fail, scan_status is FAILED and errors are collected."""
    mock_bandit = MagicMock()
    mock_bandit.run.return_value = BanditResult(
        success=False,
        exit_code=-1,
        error_message="Bandit executable not found",
    )

    mock_semgrep = MagicMock()
    mock_semgrep.run.return_value = SemgrepResult(
        success=False,
        exit_code=-1,
        error_message="Semgrep executable not found",
    )

    agent = ScanningAgent(
        bandit_runner=mock_bandit,
        semgrep_runner=mock_semgrep
    )

    findings, meta = agent.scan(tmp_path, persist=False)
    assert len(findings) == 0
    assert meta["scan_status"] == "FAILED"
    assert len(meta["errors"]) == 2
    assert "Bandit execution warning" in meta["errors"][0] or "Bandit" in meta["errors"][0]
    assert "Semgrep execution warning" in meta["errors"][1] or "Semgrep" in meta["errors"][1]
