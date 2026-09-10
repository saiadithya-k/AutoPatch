"""Unit tests for the Deterministic Risk Assessment Engine."""

import pytest
from backend.models.risk_assessment import PriorityLevel
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
)
from backend.services.risk_engine import RiskEngine


@pytest.fixture
def risk_engine() -> RiskEngine:
    return RiskEngine()


def test_risk_engine_low_severity(risk_engine: RiskEngine):
    finding = VulnerabilityFinding(
        id="VULN-LOW-01",
        tool="bandit",
        rule_id="B101",
        type="Assert Used",
        cwe="CWE-703",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        file_path="tests/test_math.py",
        line_start=10,
        description="Use of assert in test file",
    )
    assessment = risk_engine.assess_finding(finding)

    assert assessment.severity == Severity.LOW
    assert assessment.risk_score < 4.0
    assert assessment.priority == PriorityLevel.LOW
    assert 0.0 <= assessment.risk_score <= 10.0
    assert "test code" in assessment.reasoning.lower() or "test" in assessment.reasoning.lower()


def test_risk_engine_medium_severity_sql_injection(risk_engine: RiskEngine):
    finding = VulnerabilityFinding(
        id="VULN-MED-01",
        tool="bandit",
        rule_id="B608",
        type="Hardcoded Sql Expressions",
        cwe="CWE-89",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        file_path="app/database.py",
        line_start=45,
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE name={name}')",
        description="Possible SQL injection vector",
    )
    assessment = risk_engine.assess_finding(finding)

    assert assessment.severity == Severity.MEDIUM
    assert assessment.exploitability >= 8.0
    assert assessment.business_impact >= 8.0
    assert assessment.risk_score >= 7.0
    assert assessment.priority in (PriorityLevel.HIGH, PriorityLevel.CRITICAL)


def test_risk_engine_high_severity_command_injection(risk_engine: RiskEngine):
    finding = VulnerabilityFinding(
        id="VULN-HIGH-01",
        tool="bandit",
        rule_id="B605",
        type="Start Process With A Shell",
        cwe="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app/server.py",
        line_start=14,
        code_snippet="os.system(f'ping -c 1 {host}')",
        description="Starting process with a shell",
    )
    assessment = risk_engine.assess_finding(finding)

    assert assessment.severity == Severity.HIGH
    assert assessment.exploitability >= 9.0
    assert assessment.business_impact >= 9.0
    assert assessment.risk_score >= 8.5
    assert assessment.priority == PriorityLevel.CRITICAL


def test_risk_engine_critical_severity(risk_engine: RiskEngine):
    finding = VulnerabilityFinding(
        id="VULN-CRIT-01",
        tool="semgrep",
        rule_id="python.rce",
        type="Remote Code Execution",
        cwe="CWE-78",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="api/routes.py",
        line_start=99,
        description="Arbitrary remote code execution via unsafe deserialize",
    )
    assessment = risk_engine.assess_finding(finding)

    assert assessment.severity == Severity.CRITICAL
    assert assessment.risk_score >= 8.5
    assert assessment.priority == PriorityLevel.CRITICAL


def test_risk_engine_exploitability_derivation(risk_engine: RiskEngine):
    # SQLi should have high exploitability
    sqli = VulnerabilityFinding(
        id="VULN-SQL",
        tool="semgrep",
        type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.HIGH,
        file_path="database.py",
        description="Raw SQL concatenation",
    )
    assess_sqli = risk_engine.assess_finding(sqli)
    assert assess_sqli.exploitability >= 8.5

    # Test assertion should have low exploitability
    assertion = VulnerabilityFinding(
        id="VULN-ASSERT",
        tool="bandit",
        type="Assert Used",
        cwe="CWE-703",
        severity=Severity.LOW,
        file_path="tests/test_core.py",
        description="Assert in test",
    )
    assess_assert = risk_engine.assess_finding(assertion)
    assert assess_assert.exploitability <= 2.0


def test_risk_engine_business_impact_production_vs_test(risk_engine: RiskEngine):
    prod_finding = VulnerabilityFinding(
        id="VULN-PROD",
        tool="bandit",
        rule_id="B605",
        type="Command Injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        file_path="backend/services/worker.py",
        description="os.system used in worker",
    )

    test_finding = VulnerabilityFinding(
        id="VULN-TEST",
        tool="bandit",
        rule_id="B605",
        type="Command Injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        file_path="tests/test_worker.py",
        description="os.system used in test mock",
    )

    assess_prod = risk_engine.assess_finding(prod_finding)
    assess_test = risk_engine.assess_finding(test_finding)

    # Production code should have significantly higher impact and risk score than test mock
    assert assess_prod.business_impact > assess_test.business_impact
    assert assess_prod.risk_score > assess_test.risk_score


def test_risk_engine_score_bounds_and_determinism(risk_engine: RiskEngine):
    finding = VulnerabilityFinding(
        id="VULN-DET-01",
        tool="bandit",
        rule_id="B608",
        type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        file_path="app/db.py",
        line_start=25,
        description="SQL injection",
    )

    scores = [risk_engine.assess_finding(finding).risk_score for _ in range(50)]

    # Scores must be within [0.0, 10.0]
    assert all(0.0 <= s <= 10.0 for s in scores)
    # Scores must be 100% deterministic (identical on every invocation)
    assert len(set(scores)) == 1


def test_risk_engine_priority_thresholds(risk_engine: RiskEngine):
    assert risk_engine._derive_priority(10.0) == PriorityLevel.CRITICAL
    assert risk_engine._derive_priority(8.5) == PriorityLevel.CRITICAL
    assert risk_engine._derive_priority(8.49) == PriorityLevel.HIGH
    assert risk_engine._derive_priority(7.0) == PriorityLevel.HIGH
    assert risk_engine._derive_priority(6.99) == PriorityLevel.MEDIUM
    assert risk_engine._derive_priority(4.0) == PriorityLevel.MEDIUM
    assert risk_engine._derive_priority(3.99) == PriorityLevel.LOW
    assert risk_engine._derive_priority(0.0) == PriorityLevel.LOW
