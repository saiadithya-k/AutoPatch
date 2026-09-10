"""Deterministic Risk Assessment Engine.

Computes bounded (0.0 - 10.0), explainable, repeatable risk scores, exploitability,
business impact, and priority tiers for normalized vulnerability findings without
requiring external LLM dependencies.
"""

import hashlib
import re
from typing import Optional
from backend.models.risk_assessment import (
    AssessmentMethod,
    PriorityLevel,
    RiskAssessment,
    RiskContext,
)
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
)


class RiskEngine:
    """Deterministic, rule-based security risk calculation service."""

    # Formula component weights (Sum = 1.00)
    WEIGHT_SEVERITY = 0.35
    WEIGHT_EXPLOITABILITY = 0.25
    WEIGHT_BUSINESS_IMPACT = 0.25
    WEIGHT_CONTEXT = 0.15

    # Priority thresholds
    THRESHOLD_CRITICAL = 8.5
    THRESHOLD_HIGH = 7.0
    THRESHOLD_MEDIUM = 4.0

    def __init__(self):
        pass

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is part of a test suite or fixture."""
        p = file_path.lower().replace("\\", "/")
        return (
            p.startswith("test")
            or "/test" in p
            or p.endswith("_test.py")
            or p.endswith("test.py")
            or "conftest.py" in p
            or "fixtures" in p
        )

    def _extract_context(self, finding: VulnerabilityFinding) -> RiskContext:
        """Extract contextual signals from finding file path, code snippet, and description."""
        file_p = finding.file_path.lower().replace("\\", "/")
        code_s = (finding.code_snippet or "").lower()
        desc_s = finding.description.lower()
        rule_id = (finding.rule_id or "").lower()
        vuln_type = finding.type.lower()
        cwe_s = (finding.cwe or "").lower()

        is_test = self._is_test_file(file_p)

        # Database involvement
        is_db = (
            "database" in file_p
            or "db" in file_p
            or "sql" in file_p
            or "model" in file_p
            or "cwe-89" in cwe_s
            or "sql" in desc_s
            or "cursor.execute" in code_s
            or "select " in code_s
        )

        # Code execution involvement
        is_exec = (
            "cwe-78" in cwe_s
            or "cwe-95" in cwe_s
            or "eval" in desc_s
            or "system" in desc_s
            or "subprocess" in desc_s
            or "os.system" in code_s
            or "eval(" in code_s
            or "shell" in desc_s
        )

        # Auth & sensitive data
        is_auth = (
            "auth" in file_p
            or "login" in file_p
            or "token" in file_p
            or "user" in file_p
            or "password" in desc_s
            or "credential" in desc_s
            or "cwe-798" in cwe_s
        )

        # Remote / external input
        is_remote = (
            "app.py" in file_p
            or "routes" in file_p
            or "api" in file_p
            or "server" in file_p
            or "request" in code_s
            or "input" in desc_s
            or "f\"" in code_s
            or "f'" in code_s
        )

        is_sensitive = is_auth or is_db or "secret" in desc_s or "key" in desc_s

        # Confidence weighting multiplier
        conf_multiplier = 1.0
        if finding.confidence == Confidence.LOW:
            conf_multiplier = 0.85
        elif finding.confidence == Confidence.MEDIUM:
            conf_multiplier = 0.95
        elif finding.confidence == Confidence.UNDEFINED:
            conf_multiplier = 0.90

        return RiskContext(
            is_auth_involved=is_auth,
            is_database_involved=is_db,
            is_remote_input=is_remote,
            is_code_execution=is_exec,
            is_sensitive_data=is_sensitive,
            is_test_file=is_test,
            confidence_weight=conf_multiplier,
        )

    def _calculate_severity_score(self, finding: VulnerabilityFinding, context: RiskContext) -> float:
        """Compute base numerical severity score (0.0 - 10.0)."""
        base_map = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 2.5,
        }
        score = base_map.get(finding.severity, 5.0)
        # Modulate slightly with detection confidence
        score = score * context.confidence_weight
        return round(min(10.0, max(0.0, score)), 2)

    def _calculate_exploitability(self, finding: VulnerabilityFinding, context: RiskContext) -> float:
        """Compute exploitability score (0.0 - 10.0) based on vulnerability mechanics."""
        rule_id = (finding.rule_id or "").upper()
        cwe = (finding.cwe or "").upper()
        desc = finding.description.lower()
        finding_type = finding.type.lower()

        # Direct Remote Code / Command Injection
        if "CWE-78" in cwe or "CWE-95" in cwe or "B605" in rule_id or "B602" in rule_id or "B307" in rule_id or "eval" in desc:
            score = 9.5
        # SQL Injection
        elif "CWE-89" in cwe or "B608" in rule_id or "sql" in finding_type:
            score = 8.5
        # Hardcoded Credentials / Secrets
        elif "CWE-798" in cwe or "B105" in rule_id or "B106" in rule_id or "hardcoded" in finding_type:
            score = 8.0
        # Insecure Deserialization
        elif "CWE-502" in cwe or "B301" in rule_id:
            score = 7.5
        # Path Traversal
        elif "CWE-22" in cwe or "CWE-23" in cwe:
            score = 7.0
        # Assert in production vs test
        elif "B101" in rule_id or "assert" in finding_type:
            score = 1.5 if context.is_test_file else 4.0
        # Fallback by severity
        elif finding.severity == Severity.CRITICAL:
            score = 8.5
        elif finding.severity == Severity.HIGH:
            score = 7.0
        elif finding.severity == Severity.MEDIUM:
            score = 4.5
        else:
            score = 2.5

        # Modulate by remote input exposure
        if context.is_remote_input and not context.is_test_file:
            score = min(10.0, score + 0.5)

        return round(score, 2)

    def _calculate_business_impact(self, finding: VulnerabilityFinding, context: RiskContext) -> float:
        """Compute business impact score (0.0 - 10.0) based on operational risk."""
        # Test files have minimal business impact on production operations
        if context.is_test_file:
            return 1.5

        cwe = (finding.cwe or "").upper()
        rule_id = (finding.rule_id or "").upper()

        # High-impact scenarios
        if "CWE-78" in cwe or "CWE-95" in cwe or "B605" in rule_id or "B307" in rule_id:
            # Code/Command execution compromises entire host
            impact = 9.5
        elif "CWE-89" in cwe or "B608" in rule_id or context.is_database_involved:
            # SQLi risks total database read/write
            impact = 8.5
        elif "CWE-798" in cwe or "B105" in rule_id or context.is_auth_involved:
            # Auth bypass / credential exposure
            impact = 8.0
        elif finding.severity == Severity.CRITICAL:
            impact = 9.0
        elif finding.severity == Severity.HIGH:
            impact = 7.5
        elif finding.severity == Severity.MEDIUM:
            impact = 5.0
        else:
            impact = 2.5

        return round(impact, 2)

    def _calculate_context_score(self, context: RiskContext) -> float:
        """Compute contextual score (0.0 - 10.0) from environmental indicators."""
        if context.is_test_file:
            return 1.5

        base = 4.0
        if context.is_remote_input:
            base += 2.0
        if context.is_database_involved:
            base += 1.5
        if context.is_code_execution:
            base += 2.0
        if context.is_auth_involved:
            base += 1.5

        return round(min(10.0, max(1.0, base)), 2)

    def _derive_priority(self, risk_score: float) -> PriorityLevel:
        """Map numerical risk score to priority tier."""
        if risk_score >= self.THRESHOLD_CRITICAL:
            return PriorityLevel.CRITICAL
        elif risk_score >= self.THRESHOLD_HIGH:
            return PriorityLevel.HIGH
        elif risk_score >= self.THRESHOLD_MEDIUM:
            return PriorityLevel.MEDIUM
        else:
            return PriorityLevel.LOW

    def _generate_reasoning(
        self,
        finding: VulnerabilityFinding,
        context: RiskContext,
        severity_score: float,
        exploitability: float,
        impact: float,
        risk_score: float,
        priority: PriorityLevel,
    ) -> str:
        """Generate human-readable, transparent reasoning explaining the score."""
        parts = []

        # 1. Core issue classification
        parts.append(
            f"Vulnerability '{finding.type}' (Severity: {finding.severity.value}, Rule: {finding.rule_id or 'N/A'}) "
            f"identified in '{finding.file_path}' (lines {finding.line_start or 1}-{finding.line_end or 1})."
        )

        # 2. Context & File Role
        if context.is_test_file:
            parts.append(
                "Context: Finding is located within test code/fixtures, which significantly lowers production exposure and operational impact."
            )
        else:
            context_highlights = []
            if context.is_code_execution:
                context_highlights.append("dynamic code/shell execution capability")
            if context.is_database_involved:
                context_highlights.append("database access/query construction")
            if context.is_remote_input:
                context_highlights.append("direct interaction with external input/routes")
            if context.is_auth_involved:
                context_highlights.append("authentication/credential processing")

            if context_highlights:
                parts.append(f"Context: Involves {', '.join(context_highlights)}.")

        # 3. Exploitability & Impact Breakdown
        parts.append(
            f"Exploitability is assessed at {exploitability:.1f}/10.0 due to vulnerability mechanics, "
            f"and potential Business Impact is rated at {impact:.1f}/10.0."
        )

        # 4. Final Score & Priority Verdict
        parts.append(
            f"Applying weighted deterministic scoring yields an overall Risk Score of {risk_score:.2f}/10.0, "
            f"classifying this finding as {priority.value} priority for remediation."
        )

        return " ".join(parts)

    def assess_finding(
        self,
        finding: VulnerabilityFinding,
        workflow_id: Optional[str] = None
    ) -> RiskAssessment:
        """
        Evaluate a single normalized vulnerability finding and produce a complete RiskAssessment.

        :param finding: Normalized VulnerabilityFinding instance.
        :param workflow_id: Optional workflow ID.
        :return: Strongly typed RiskAssessment record.
        """
        context = self._extract_context(finding)

        severity_score = self._calculate_severity_score(finding, context)
        exploitability = self._calculate_exploitability(finding, context)
        impact = self._calculate_business_impact(finding, context)
        context_score = self._calculate_context_score(context)

        # Weighted calculation
        raw_risk = (
            (self.WEIGHT_SEVERITY * severity_score)
            + (self.WEIGHT_EXPLOITABILITY * exploitability)
            + (self.WEIGHT_BUSINESS_IMPACT * impact)
            + (self.WEIGHT_CONTEXT * context_score)
        )
        final_risk = round(min(10.0, max(0.0, raw_risk)), 2)

        priority = self._derive_priority(final_risk)

        reasoning = self._generate_reasoning(
            finding=finding,
            context=context,
            severity_score=severity_score,
            exploitability=exploitability,
            impact=impact,
            risk_score=final_risk,
            priority=priority,
        )

        # Deterministic assessment ID
        raw_key = f"{workflow_id or 'wf'}:{finding.id}:{final_risk}"
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:8].upper()
        assessment_id = f"RISK-{digest}"

        return RiskAssessment(
            id=assessment_id,
            vulnerability_id=finding.id,
            workflow_id=workflow_id or finding.workflow_id,
            severity=finding.severity,
            severity_score=severity_score,
            exploitability=exploitability,
            business_impact=impact,
            context_score=context_score,
            risk_score=final_risk,
            priority=priority,
            reasoning=reasoning,
            assessment_method=AssessmentMethod.DETERMINISTIC_RULES,
            model=None,
            context=context,
        )
