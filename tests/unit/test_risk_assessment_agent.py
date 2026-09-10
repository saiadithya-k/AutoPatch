"""Unit tests for RiskAssessmentAgent."""

import pytest
from sqlalchemy.orm import Session

from backend.agents.risk_assessment_agent import RiskAssessmentAgent
from backend.database.models import RiskAssessmentModel, VulnerabilityModel, WorkflowModel
from backend.models.risk_assessment import PriorityLevel
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
    WorkflowStatus,
)


@pytest.fixture
def risk_agent() -> RiskAssessmentAgent:
    return RiskAssessmentAgent()


def test_risk_agent_empty_list(risk_agent: RiskAssessmentAgent):
    results = risk_agent.assess([], persist=False)
    assert results == []


def test_risk_agent_single_finding_and_status_transitions(risk_agent: RiskAssessmentAgent):
    finding = VulnerabilityFinding(
        id="VULN-001",
        tool="bandit",
        rule_id="B605",
        type="Command Injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_start=14,
        description="os.system used with user input",
        status=VulnerabilityStatus.DETECTED,
    )

    prioritized = risk_agent.assess([finding], persist=False)

    assert len(prioritized) == 1
    p = prioritized[0]
    assert p.rank == 1
    assert p.vulnerability.id == "VULN-001"
    assert p.vulnerability.status == VulnerabilityStatus.PRIORITIZED
    assert p.risk_assessment.risk_score > 7.0
    assert p.risk_assessment.priority in (PriorityLevel.CRITICAL, PriorityLevel.HIGH)
    assert p.risk_assessment.vulnerability_id == "VULN-001"
    assert len(p.risk_assessment.reasoning) > 20


def test_risk_agent_multiple_findings_sorting_and_ranking(risk_agent: RiskAssessmentAgent):
    f_low = VulnerabilityFinding(
        id="VULN-LOW",
        tool="bandit",
        rule_id="B101",
        type="Assert Used",
        cwe="CWE-703",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        file_path="tests/test_app.py",
        line_start=10,
        description="Assert in test",
        status=VulnerabilityStatus.DETECTED,
    )

    f_high = VulnerabilityFinding(
        id="VULN-HIGH",
        tool="bandit",
        rule_id="B605",
        type="Start Process With A Shell",
        cwe="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_start=14,
        description="Command injection in app",
        status=VulnerabilityStatus.DETECTED,
    )

    f_med = VulnerabilityFinding(
        id="VULN-MED",
        tool="bandit",
        rule_id="B608",
        type="Hardcoded Sql Expressions",
        cwe="CWE-89",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        file_path="database.py",
        line_start=25,
        description="SQL injection in database",
        status=VulnerabilityStatus.DETECTED,
    )

    prioritized = risk_agent.assess([f_low, f_high, f_med], persist=False)

    assert len(prioritized) == 3
    # Sorted descending by risk score
    assert prioritized[0].vulnerability.id == "VULN-HIGH"
    assert prioritized[0].rank == 1

    assert prioritized[1].vulnerability.id == "VULN-MED"
    assert prioritized[1].rank == 2

    assert prioritized[2].vulnerability.id == "VULN-LOW"
    assert prioritized[2].rank == 3

    assert prioritized[0].risk_assessment.risk_score >= prioritized[1].risk_assessment.risk_score
    assert prioritized[1].risk_assessment.risk_score >= prioritized[2].risk_assessment.risk_score


def test_risk_agent_database_persistence(risk_agent: RiskAssessmentAgent, db_session: Session):
    wf_id = "wf-test-risk-001"
    wf = WorkflowModel(
        id=wf_id,
        repository_path="/test/repo",
        status=WorkflowStatus.SCANNING.value,
    )
    db_session.add(wf)

    vuln = VulnerabilityModel(
        id="VULN-DB-001",
        workflow_id=wf_id,
        tool="bandit",
        rule_id="B608",
        type="SQL Injection",
        cwe="CWE-89",
        severity=Severity.MEDIUM.value,
        file_path="database.py",
        description="SQL injection flaw",
        status=VulnerabilityStatus.DETECTED.value,
    )
    db_session.add(vuln)
    db_session.commit()

    prioritized = risk_agent.assess_workflow(
        workflow_id=wf_id,
        persist=True,
        db_session=db_session
    )

    assert len(prioritized) == 1
    assert prioritized[0].rank == 1

    # Verify risk_assessments table in database
    ra_record = db_session.query(RiskAssessmentModel).filter(
        RiskAssessmentModel.vulnerability_id == "VULN-DB-001"
    ).first()
    assert ra_record is not None
    assert ra_record.risk_score > 5.0
    assert ra_record.priority in (PriorityLevel.HIGH.value, PriorityLevel.CRITICAL.value)

    # Verify updated vulnerability record in database
    updated_vuln = db_session.query(VulnerabilityModel).filter(
        VulnerabilityModel.id == "VULN-DB-001"
    ).first()
    assert updated_vuln.status == VulnerabilityStatus.PRIORITIZED.value
    assert updated_vuln.risk_score == ra_record.risk_score
    assert updated_vuln.priority == ra_record.priority
    assert updated_vuln.risk_reasoning is not None

    # Verify updated workflow record
    updated_wf = db_session.query(WorkflowModel).filter(WorkflowModel.id == wf_id).first()
    assert updated_wf.status == WorkflowStatus.RISK_ASSESSMENT.value
