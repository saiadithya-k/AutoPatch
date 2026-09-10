"""AutoPatch Risk-Assessment Agent.

Consumes normalized vulnerability findings, applies the deterministic risk engine,
assigns remediation priorities, produces human-readable risk explanations,
and persists prioritized findings to the database.
"""

import logging
from typing import Any, Optional

from backend.database.database import session_scope
from backend.database.models import RiskAssessmentModel, VulnerabilityModel, WorkflowModel, utc_now
from backend.models.risk_assessment import (
    AssessmentMethod,
    PrioritizedVulnerability,
    RiskAssessment,
)
from backend.models.vulnerability import (
    VulnerabilityFinding,
    VulnerabilityStatus,
    WorkflowStatus,
)
from backend.services.llm.service import LLMService
from backend.services.risk_engine import RiskEngine

logger = logging.getLogger(__name__)


class RiskAssessmentAgent:
    """Specialized Agent responsible for triaging, assessing risk, and prioritizing vulnerabilities."""

    def __init__(
        self,
        risk_engine: Optional[RiskEngine] = None,
        llm_service: Optional[LLMService] = None,
        enable_llm: bool = False,
    ):
        """
        Initialize Risk-Assessment Agent with risk calculation engine and optional LLM service.

        :param risk_engine: Deterministic risk engine instance.
        :param llm_service: Optional LLM service for structured contextual enhancement.
        :param enable_llm: Whether to invoke LLM contextual reasoning.
        """
        self.risk_engine = risk_engine or RiskEngine()
        self.llm_service = llm_service
        self.enable_llm = enable_llm

    def assess(
        self,
        findings: list[VulnerabilityFinding],
        workflow_id: Optional[str] = None,
        persist: bool = True,
        db_session: Optional[Any] = None,
    ) -> list[PrioritizedVulnerability]:
        """
        Evaluate a collection of normalized vulnerability findings and produce prioritized records.

        Steps:
        1. Inspect each vulnerability finding and contextual data.
        2. Execute deterministic risk engine to compute severity, exploitability, impact, risk score, and priority.
        3. Optionally query LLM for structured contextual reasoning (hybrid mode).
        4. Update finding lifecycle status (DETECTED -> ASSESSED -> PRIORITIZED).
        5. Sort all findings in descending order of risk score (highest risk first).
        6. Assign 1-indexed priority ranks.
        7. Persist risk assessment records and update vulnerability rows if persist=True.

        :param findings: List of normalized VulnerabilityFinding instances.
        :param workflow_id: Optional workflow run ID.
        :param persist: Whether to persist results to the database.
        :param db_session: Optional active SQLAlchemy session.
        :return: Ranked list of PrioritizedVulnerability instances.
        """
        if not findings:
            logger.info("No vulnerability findings supplied for risk assessment.")
            return []

        logger.info(
            "Starting risk assessment for %d findings (Workflow: %s, LLM Enabled: %s)",
            len(findings),
            workflow_id or "N/A",
            self.enable_llm,
        )

        assessed_pairs: list[tuple[VulnerabilityFinding, RiskAssessment]] = []

        for finding in findings:
            # 1. Transition: DETECTED -> ASSESSED
            finding.status = VulnerabilityStatus.ASSESSED

            # 2. Compute deterministic risk assessment
            assessment = self.risk_engine.assess_finding(
                finding=finding,
                workflow_id=workflow_id or finding.workflow_id
            )

            # 3. Optional structured LLM contextual enhancement
            if self.enable_llm and self.llm_service and self.llm_service.is_configured:
                try:
                    llm_analysis = self.llm_service.enhance_risk_reasoning(
                        finding=finding,
                        baseline_reasoning=assessment.reasoning,
                    )
                    if llm_analysis:
                        combined_reasoning = LLMService.format_hybrid_reasoning(
                            baseline_reasoning=assessment.reasoning,
                            llm_analysis=llm_analysis,
                        )
                        assessment.reasoning = combined_reasoning
                        assessment.assessment_method = AssessmentMethod.HYBRID_LLM
                        assessment.model = self.llm_service.provider.model if self.llm_service.provider else "llm"
                except Exception as e:
                    logger.warning(
                        "LLM contextual reasoning failed for %s, safely falling back to deterministic baseline: %s",
                        finding.id,
                        e,
                    )

            # 4. Transition: ASSESSED -> PRIORITIZED & enrich finding
            finding.status = VulnerabilityStatus.PRIORITIZED
            finding.exploitability = assessment.exploitability
            finding.business_impact = assessment.business_impact
            finding.risk_score = assessment.risk_score
            finding.priority = assessment.priority.value
            finding.risk_reasoning = assessment.reasoning

            assessed_pairs.append((finding, assessment))

            logger.debug(
                "Assessed %s: Score=%.2f, Priority=%s",
                finding.id,
                assessment.risk_score,
                assessment.priority.value
            )

        # 4. Sort descending by risk score (highest risk first)
        assessed_pairs.sort(key=lambda pair: pair[1].risk_score, reverse=True)

        # 5. Build ranked PrioritizedVulnerability models
        prioritized_results: list[PrioritizedVulnerability] = []
        for rank_idx, (finding, assessment) in enumerate(assessed_pairs, start=1):
            prioritized_results.append(
                PrioritizedVulnerability(
                    vulnerability=finding,
                    risk_assessment=assessment,
                    rank=rank_idx
                )
            )

        # 6. Persist to database
        if persist:
            target_wf_id = workflow_id or (findings[0].workflow_id if findings else None)
            self._persist_assessments(
                workflow_id=target_wf_id,
                prioritized_list=prioritized_results,
                db_session=db_session
            )

        logger.info(
            "Risk assessment complete for %d findings. Top risk: %s (Score: %.2f, Priority: %s)",
            len(prioritized_results),
            prioritized_results[0].vulnerability.id if prioritized_results else "N/A",
            prioritized_results[0].risk_assessment.risk_score if prioritized_results else 0.0,
            prioritized_results[0].risk_assessment.priority.value if prioritized_results else "N/A"
        )

        return prioritized_results

    def assess_workflow(
        self,
        workflow_id: str,
        persist: bool = True,
        db_session: Optional[Any] = None,
    ) -> list[PrioritizedVulnerability]:
        """
        Load persisted vulnerability findings for a workflow from the database and perform risk assessment.

        :param workflow_id: Workflow execution identifier.
        :param persist: Whether to save assessment results back to the database.
        :param db_session: Optional active SQLAlchemy session.
        :return: Ranked list of PrioritizedVulnerability instances.
        """
        findings: list[VulnerabilityFinding] = []

        def _fetch(session):
            nonlocal findings
            records = session.query(VulnerabilityModel).filter(
                VulnerabilityModel.workflow_id == workflow_id
            ).all()

            for r in records:
                raw_data = r.get_raw_finding()
                findings.append(
                    VulnerabilityFinding(
                        id=r.id,
                        workflow_id=r.workflow_id,
                        tool=r.tool,
                        rule_id=r.rule_id,
                        type=r.type,
                        cwe=r.cwe,
                        severity=r.severity,
                        confidence=r.confidence,
                        file_path=r.file_path,
                        line_start=r.line_start,
                        line_end=r.line_end,
                        code_snippet=r.code_snippet,
                        description=r.description,
                        raw_finding=raw_data,
                        exploitability=r.exploitability,
                        business_impact=r.business_impact,
                        risk_score=r.risk_score,
                        priority=r.priority,
                        risk_reasoning=r.risk_reasoning,
                        status=VulnerabilityStatus(r.status) if r.status in VulnerabilityStatus.__members__ else VulnerabilityStatus.DETECTED,
                        created_at=r.created_at,
                    )
                )

        if db_session is not None:
            _fetch(db_session)
        else:
            with session_scope() as session:
                _fetch(session)

        return self.assess(
            findings=findings,
            workflow_id=workflow_id,
            persist=persist,
            db_session=db_session
        )

    def _execute_in_session(self, db_session: Optional[Any], fn) -> None:
        """Execute callback either in provided session or a new scoped session."""
        if db_session is not None:
            fn(db_session)
            db_session.commit()
        else:
            with session_scope() as session:
                fn(session)

    def _persist_assessments(
        self,
        workflow_id: Optional[str],
        prioritized_list: list[PrioritizedVulnerability],
        db_session: Optional[Any] = None
    ) -> None:
        """Persist risk assessments and update vulnerability records."""
        now = utc_now()

        def _do(session):
            if workflow_id:
                wf = session.query(WorkflowModel).filter(WorkflowModel.id == workflow_id).first()
                if wf:
                    wf.status = WorkflowStatus.RISK_ASSESSMENT.value
                    wf.current_stage = "RISK_ASSESSMENT_COMPLETE"

            for item in prioritized_list:
                finding = item.vulnerability
                assessment = item.risk_assessment

                # 1. Update or create RiskAssessmentModel
                existing_ra = session.query(RiskAssessmentModel).filter(
                    RiskAssessmentModel.vulnerability_id == finding.id
                ).first()

                if existing_ra:
                    existing_ra.severity = assessment.severity.value
                    existing_ra.severity_score = assessment.severity_score
                    existing_ra.exploitability = assessment.exploitability
                    existing_ra.business_impact = assessment.business_impact
                    existing_ra.context_score = assessment.context_score
                    existing_ra.risk_score = assessment.risk_score
                    existing_ra.priority = assessment.priority.value
                    existing_ra.reasoning = assessment.reasoning
                    existing_ra.assessment_method = assessment.assessment_method.value
                    existing_ra.model = assessment.model
                else:
                    ra_model = RiskAssessmentModel(
                        id=assessment.id,
                        vulnerability_id=finding.id,
                        workflow_id=workflow_id or finding.workflow_id,
                        severity=assessment.severity.value,
                        severity_score=assessment.severity_score,
                        exploitability=assessment.exploitability,
                        business_impact=assessment.business_impact,
                        context_score=assessment.context_score,
                        risk_score=assessment.risk_score,
                        priority=assessment.priority.value,
                        reasoning=assessment.reasoning,
                        assessment_method=assessment.assessment_method.value,
                        model=assessment.model,
                        created_at=now,
                    )
                    session.add(ra_model)

                # 2. Update cached fields on VulnerabilityModel
                vuln_record = session.query(VulnerabilityModel).filter(
                    VulnerabilityModel.id == finding.id
                ).first()

                if vuln_record:
                    vuln_record.exploitability = assessment.exploitability
                    vuln_record.business_impact = assessment.business_impact
                    vuln_record.risk_score = assessment.risk_score
                    vuln_record.priority = assessment.priority.value
                    vuln_record.risk_reasoning = assessment.reasoning
                    vuln_record.status = VulnerabilityStatus.PRIORITIZED.value
                    vuln_record.updated_at = now

        self._execute_in_session(db_session, _do)
