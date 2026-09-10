"""Integration tests running real Bandit and Semgrep scanners against the demo vulnerable project."""

from pathlib import Path
import pytest

from backend.agents.scanning_agent import ScanningAgent
from backend.models.vulnerability import Severity, VulnerabilityStatus


def test_real_scan_vulnerable_project_end_to_end(vulnerable_repo_path: Path):
    """
    Execute real Bandit and Semgrep scan against tests/vulnerable_project.
    Verify normalized findings, deduplication, and metadata.
    """
    agent = ScanningAgent()
    findings, metadata = agent.scan(vulnerable_repo_path, persist=False)

    # Must find at least 2 real security vulnerabilities (SQLi and Command Injection / Eval)
    assert len(findings) >= 2
    assert metadata["bandit"]["success"] is True
    assert metadata["semgrep"]["success"] is True

    file_paths = {f.file_path for f in findings}
    assert "app.py" in file_paths
    assert "database.py" in file_paths

    # Verify SQL injection finding
    sqli_findings = [f for f in findings if f.file_path == "database.py" and f.line_start == 25]
    assert len(sqli_findings) == 1
    sqli = sqli_findings[0]
    assert sqli.cwe == "CWE-89" or "Sql" in sqli.type
    assert sqli.status == VulnerabilityStatus.DETECTED
    assert sqli.id.startswith("VULN-")

    # Verify Command Injection / Eval finding
    app_findings = [f for f in findings if f.file_path == "app.py"]
    assert len(app_findings) >= 2


def test_real_scan_clean_repository(temp_clean_repo: Path):
    """
    Execute real Bandit and Semgrep scan against clean repository.
    Verify zero vulnerabilities reported.
    """
    agent = ScanningAgent()
    findings, metadata = agent.scan(temp_clean_repo, persist=False)

    assert len(findings) == 0
    assert metadata["bandit"]["success"] is True
    assert metadata["semgrep"]["success"] is True
