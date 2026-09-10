"""Unit tests for finding normalization and deduplication logic."""

from pathlib import Path
import pytest

from backend.agents.scanning_agent import ScanningAgent
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
)


def test_bandit_finding_normalization():
    agent = ScanningAgent()
    repo_root = Path("/tmp/mock_repo")

    raw_bandit = {
        "test_id": "B608",
        "test_name": "hardcoded_sql_expressions",
        "issue_text": "Possible SQL injection vector through string-based query construction.",
        "issue_severity": "MEDIUM",
        "issue_confidence": "LOW",
        "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
        "filename": str(repo_root / "database.py"),
        "line_number": 25,
        "line_range": [25],
        "code": "cursor.execute(query)",
    }

    norm = agent._normalize_bandit_finding(raw_bandit, repo_root, "wf-123")

    assert norm.workflow_id == "wf-123"
    assert norm.tool == "bandit"
    assert norm.rule_id == "B608"
    assert norm.severity == Severity.MEDIUM
    assert norm.confidence == Confidence.LOW
    assert norm.cwe == "CWE-89"
    assert norm.file_path == "database.py"
    assert norm.line_start == 25
    assert norm.status == VulnerabilityStatus.DETECTED
    assert norm.id.startswith("VULN-")


def test_semgrep_finding_normalization():
    agent = ScanningAgent()
    repo_root = Path("/tmp/mock_repo")

    raw_semgrep = {
        "check_id": "python.lang.security.audit.eval-detected",
        "path": str(repo_root / "app.py"),
        "start": {"line": 23, "col": 12},
        "end": {"line": 23, "col": 32},
        "extra": {
            "message": "Detected use of eval().",
            "severity": "ERROR",
            "metadata": {
                "cwe": ["CWE-95"],
                "confidence": "HIGH",
                "category": "security",
            },
            "lines": "return eval(expression_str)",
        },
    }

    norm = agent._normalize_semgrep_finding(raw_semgrep, repo_root, "wf-123")

    assert norm.workflow_id == "wf-123"
    assert norm.tool == "semgrep"
    assert norm.rule_id == "python.lang.security.audit.eval-detected"
    assert norm.severity == Severity.HIGH
    assert norm.confidence == Confidence.HIGH
    assert norm.cwe == "CWE-95"
    assert norm.file_path == "app.py"
    assert norm.line_start == 23
    assert norm.code_snippet == "return eval(expression_str)"
    assert norm.id.startswith("VULN-")


def test_deduplication_overlapping_findings():
    agent = ScanningAgent()

    finding1 = VulnerabilityFinding(
        id="VULN-1",
        tool="bandit",
        rule_id="B307",
        type="Blacklist Eval",
        cwe="CWE-95",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        file_path="app.py",
        line_start=23,
        line_end=23,
        description="Bandit detected eval",
    )

    finding2 = VulnerabilityFinding(
        id="VULN-2",
        tool="semgrep",
        rule_id="python.eval-detected",
        type="Eval Detected",
        cwe="CWE-95",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_start=23,
        line_end=23,
        description="Semgrep detected eval",
    )

    finding3 = VulnerabilityFinding(
        id="VULN-3",
        tool="bandit",
        rule_id="B608",
        type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.MEDIUM,
        file_path="database.py",
        line_start=45,
        description="SQL injection in database",
    )

    deduped = agent._deduplicate_findings([finding1, finding2, finding3])

    assert len(deduped) == 2
    merged = [f for f in deduped if f.file_path == "app.py"][0]
    assert "bandit" in merged.tool
    assert "semgrep" in merged.tool
    # Merged finding should pick higher severity (HIGH over MEDIUM)
    assert merged.severity == Severity.HIGH
