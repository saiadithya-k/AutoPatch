"""AutoPatch Patch-Generation Agent.

Consumes prioritized vulnerability findings, risk assessments, and repository context,
formats prompt templates with strict untrusted data boundaries, calls the provider-independent
LLM service, validates candidate patches structurally, computes unified diffs, and persists
patch attempts without modifying the original repository on disk.
"""

import difflib
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from backend.config import get_settings
from backend.database.database import session_scope
from backend.database.models import (
    PatchAttemptModel,
    RiskAssessmentModel,
    VulnerabilityModel,
    WorkflowModel,
    utc_now,
)
from backend.models.patch import (
    PatchFileChange,
    PatchGenerationResult,
    PatchStatus,
)
from backend.models.repository_context import RepositoryContext
from backend.models.risk_assessment import (
    AssessmentMethod,
    PriorityLevel,
    RiskAssessment,
)
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
    WorkflowStatus,
)
from backend.services.llm.exceptions import LLMError
from backend.services.llm.schemas import (
    LLMCodeChange,
    LLMPatchGeneration,
)
from backend.services.llm.service import LLMService
from backend.services.repository_context import RepositoryContextService

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent / "prompts"


class PatchGenerationAgent:
    """Specialized Agent responsible for synthesizing minimal, candidate vulnerability patches."""

    def __init__(
        self,
        llm_service: Optional[LLMService] = None,
        repository_context_service: Optional[RepositoryContextService] = None,
        max_patch_files: Optional[int] = None,
        max_patch_lines: Optional[int] = None,
        max_patch_chars: Optional[int] = None,
    ):
        """
        Initialize Patch-Generation Agent.

        :param llm_service: Provider-independent LLM service instance.
        :param repository_context_service: Service for extracting bounded code context.
        :param max_patch_files: Maximum allowed files in a single patch proposal.
        :param max_patch_lines: Maximum total lines allowed in candidate diff.
        :param max_patch_chars: Maximum characters allowed in candidate diff.
        """
        settings = get_settings()
        self.llm_service = llm_service or LLMService()
        self.repository_context_service = repository_context_service or RepositoryContextService()
        self.max_patch_files = max_patch_files or settings.MAX_PATCH_FILES
        self.max_patch_lines = max_patch_lines or settings.MAX_PATCH_LINES
        self.max_patch_chars = max_patch_chars or settings.MAX_PATCH_CHARS

    def _load_prompt_template(self) -> str:
        """Safely load the patch generation system prompt template from disk."""
        prompt_file = PROMPTS_DIR / "patch_generation.md"
        if prompt_file.exists():
            try:
                return prompt_file.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning("Failed to load prompts/patch_generation.md: %s", e)

        return (
            "You are an expert automated security remediation specialist. "
            "Generate a minimal, precise, syntax-valid Python patch in JSON format."
        )

    def _format_user_prompt(
        self,
        vulnerability: VulnerabilityFinding,
        risk_assessment: Optional[RiskAssessment],
        context: RepositoryContext,
        attempt_number: int = 1,
        feedback: Optional[str] = None,
    ) -> str:
        """
        Format the user prompt with strict untrusted data boundaries.
        Treats all repository code, snippets, and comments strictly as passive data.
        """
        imports_summary = "\n".join(
            f"  - {imp.raw_statement}" for imp in context.imports
        ) if context.imports else "  - None detected"

        related_files_summary = "\n".join(
            f"  - {rf.file_path} ({rf.relationship})" for rf in context.related_files
        ) if context.related_files else "  - None"

        related_tests_summary = "\n".join(
            f"  - {rt.file_path} (tests: {', '.join(rt.test_names) if rt.test_names else 'all'})"
            for rt in context.related_tests
        ) if context.related_tests else "  - None"

        scope_desc = "Module-level code"
        if context.enclosing_scope:
            scope_desc = f"{context.enclosing_scope.scope_type} '{context.enclosing_scope.name}' (lines {context.enclosing_scope.line_start}-{context.enclosing_scope.line_end})"

        risk_score_str = f"{risk_assessment.risk_score:.2f}/10.0" if risk_assessment else "N/A"
        priority_str = risk_assessment.priority.value if risk_assessment else "N/A"
        reasoning_str = risk_assessment.reasoning if risk_assessment else "N/A"

        feedback_block = ""
        if feedback:
            feedback_block = f"""
<retry_feedback>
Previous patch attempt failed validation. Please incorporate this feedback:
{feedback}
</retry_feedback>
"""

        prompt = f"""Please generate a candidate security patch for the following prioritized vulnerability finding:

<finding_metadata>
Finding ID: {vulnerability.id}
Vulnerability Type: {vulnerability.type}
Severity: {vulnerability.severity.value}
CWE: {vulnerability.cwe or 'N/A'}
Rule ID: {vulnerability.rule_id or 'N/A'}
File Path: {vulnerability.file_path}
Vulnerable Lines: {vulnerability.line_start or 1} to {vulnerability.line_end or 1}
Risk Score: {risk_score_str}
Priority: {priority_str}
Risk Reasoning: {reasoning_str}
Attempt: #{attempt_number}
</finding_metadata>

<untrusted_source_context>
Target File: {context.vulnerable_file}
Language: {context.language}
Enclosing Scope: {scope_desc}
Context Window Lines: {context.context_window_start} - {context.context_window_end} (of {context.total_file_lines} total lines)

Available Imports in File:
{imports_summary}

Surrounding Code (±{self.repository_context_service.context_lines_before} lines):
```python
{context.surrounding_code}
```
</untrusted_source_context>

<related_files_context>
Discovered Related Source Files:
{related_files_summary}

Discovered Associated Tests:
{related_tests_summary}
</related_files_context>
{feedback_block}
INSTRUCTION: Output MUST be a single valid JSON object adhering strictly to the LLMPatchGeneration schema. Do not modify any test files. Provide minimal code changes only.
"""
        return prompt

    def _generate_unified_diff(
        self,
        file_path: str,
        original_source: str,
        changes: list[LLMCodeChange],
        context_window_start: int = 1,
    ) -> tuple[str, list[str]]:
        """
        Synthesize a standard unified diff by applying structured code changes to original source.
        Uses exact original code matching where possible to prevent context drift.

        :param file_path: Relative path of the modified file.
        :param original_source: Full or windowed original source code text.
        :param changes: List of LLMCodeChange blocks for this file.
        :param context_window_start: 1-indexed start line of original_source relative to the full file.
        :return: Tuple of (unified_diff_string, list_of_warnings).
        """
        warnings: list[str] = []
        orig_lines = original_source.splitlines(keepends=True)
        if not orig_lines and original_source:
            orig_lines = [original_source]

        modified_lines = list(orig_lines)

        for change in changes:
            # 1. Attempt exact original code matching in source lines
            target_code = change.original_code.strip()
            matched_start = None
            matched_end = None

            if target_code:
                orig_stripped = [l.strip() for l in orig_lines]
                target_lines = [l.strip() for l in target_code.splitlines() if l.strip()]
                target_len = len(target_lines)

                if target_len > 0:
                    for idx in range(len(orig_stripped) - target_len + 1):
                        if orig_stripped[idx : idx + target_len] == target_lines:
                            matched_start = idx
                            matched_end = idx + target_len
                            break

            if matched_start is not None and matched_end is not None:
                start_idx = matched_start
                end_idx = matched_end
            else:
                # Fall back to 1-indexed coordinates adjusted by window start
                offset = max(0, context_window_start - 1)
                start_idx = max(0, change.start_line - 1 - offset)
                end_idx = min(len(modified_lines), change.end_line - offset)

            # Replace lines in modified buffer
            replacement = change.replacement_code
            repl_lines = replacement.splitlines(keepends=True) if replacement else []
            if replacement and not replacement.endswith("\n") and repl_lines:
                repl_lines[-1] = repl_lines[-1] + "\n"

            # Apply replacement in copy
            modified_lines[start_idx:end_idx] = repl_lines

        # Produce unified diff
        diff_lines = list(
            difflib.unified_diff(
                orig_lines,
                modified_lines,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="\n",
            )
        )

        diff_str = "".join(diff_lines).strip()
        return diff_str, warnings

    def _parse_diff_file_headers(self, unified_diff: str) -> list[tuple[str, str]]:
        """
        Independently extract all (from_file, to_file) paths from standard unified diff headers.
        """
        pairs: list[tuple[str, str]] = []
        lines = unified_diff.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("--- "):
                from_part = line[4:].strip().split("\t")[0]
                if i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
                    to_part = lines[i + 1][4:].strip().split("\t")[0]
                    # Strip Git prefixes
                    if from_part.startswith("a/"):
                        from_part = from_part[2:]
                    if to_part.startswith("b/"):
                        to_part = to_part[2:]
                    pairs.append((from_part, to_part))
                    i += 2
                    continue
            i += 1
        return pairs

    def _validate_patch_safety(
        self,
        context: RepositoryContext,
        llm_patch: LLMPatchGeneration,
        unified_diff: str,
    ) -> tuple[bool, list[str]]:
        """
        Perform rigorous safety and structural validation on the generated candidate patch.

        Checks:
        1. Unified diff is non-empty and well-formed.
        2. Diff headers are valid and from_file matches to_file.
        3. Structured changes list and unified diff files are in complete concordance.
        4. No path traversal (../, absolute paths, drive letters, UNC paths).
        5. No test file modifications.
        6. All modified files are within repository context.
        7. Patch size limits (files, lines, chars) remain strictly bounded.

        :return: Tuple of (is_safe: bool, warnings: list[str]).
        """
        warnings: list[str] = []

        if not unified_diff or not unified_diff.strip():
            warnings.append("empty_diff: Model produced no code modifications.")
            return False, warnings

        # 1. Independently parse unified diff file headers
        diff_file_pairs = self._parse_diff_file_headers(unified_diff)
        if not diff_file_pairs:
            warnings.append("invalid_diff: Could not parse standard unified diff headers (--- a/ +++ b/).")
            return False, warnings

        diff_files: set[str] = set()
        for from_f, to_f in diff_file_pairs:
            # Check for unexpected new or deleted files
            if from_f == "/dev/null" or to_f == "/dev/null":
                warnings.append("unexpected_file_modification: Adding or deleting entire files is not permitted.")
                return False, warnings

            norm_from = from_f.replace("\\", "/").strip()
            norm_to = to_f.replace("\\", "/").strip()

            if norm_from != norm_to:
                warnings.append(
                    f"diff_header_mismatch: Diff header mismatch: '--- a/{from_f}' vs '+++ b/{to_f}'."
                )
                return False, warnings

            diff_files.add(norm_from)

        # 2. Concordance check between LLMPatchGeneration.changes and unified diff
        if llm_patch.changes:
            changes_files = {c.file_path.replace("\\", "/").strip() for c in llm_patch.changes}
            if len(changes_files) > self.max_patch_files:
                warnings.append(
                    f"too_many_files: Patch touches {len(changes_files)} files in changes list, exceeding limit ({self.max_patch_files})."
                )
                return False, warnings

            if changes_files != diff_files:
                warnings.append(
                    f"diff_changes_mismatch: Changed files in structured changes ({sorted(changes_files)}) "
                    f"do not match diff headers ({sorted(diff_files)})."
                )
                return False, warnings

        changed_files = list(diff_files)

        # Limit 1: File count limit
        if len(changed_files) > self.max_patch_files:
            warnings.append(
                f"too_many_files: Patch touches {len(changed_files)} files, exceeding limit ({self.max_patch_files})."
            )
            return False, warnings

        # Limit 2: Diff line length limit
        diff_line_count = len(unified_diff.splitlines())
        if diff_line_count > self.max_patch_lines:
            warnings.append(
                f"diff_too_large: Diff length ({diff_line_count} lines) exceeds limit ({self.max_patch_lines} lines)."
            )
            return False, warnings

        # Limit 3: Diff character limit
        if len(unified_diff) > self.max_patch_chars:
            warnings.append(
                f"diff_chars_exceeded: Diff size ({len(unified_diff)} chars) exceeds limit ({self.max_patch_chars})."
            )
            return False, warnings

        # Path Security Checks on each changed file
        for f in changed_files:
            # Check 1: Traversal escape
            if ".." in f.split("/"):
                warnings.append(f"path_traversal_rejected: Path '{f}' attempts directory traversal.")
                return False, warnings

            # Check 2: Absolute path escape
            if f.startswith("/") or (len(f) > 1 and f[1] == ":") or f.startswith("\\"):
                warnings.append(f"absolute_path_rejected: Path '{f}' is an absolute or UNC path.")
                return False, warnings

            # Check 3: Test file protection
            p = Path(f)
            if (
                p.name.startswith("test_")
                or p.name.endswith("_test.py")
                or "tests/" in f.lower()
                or "test/" in f.lower()
            ):
                warnings.append(
                    f"test_modification_rejected: Patch attempts to modify test file '{f}'."
                )
                return False, warnings

            # Check 4: Context relevance
            is_target_vuln = (f == context.vulnerable_file or f.endswith(context.vulnerable_file))
            is_related = any(f == rf.file_path or f.endswith(rf.file_path) for rf in context.related_files)

            if not (is_target_vuln or is_related):
                warnings.append(
                    f"unrelated_file_rejected: File '{f}' is not the vulnerable file or an identified related file."
                )
                return False, warnings

        return True, warnings

    def generate_patch(
        self,
        vulnerability: VulnerabilityFinding,
        risk_assessment: Optional[RiskAssessment] = None,
        repository_context: Optional[RepositoryContext] = None,
        attempt_number: int = 1,
        feedback: Optional[str] = None,
        persist: bool = True,
        db_session: Optional[Any] = None,
        parent_patch_id: Optional[str] = None,
        retry_reason: Optional[str] = None,
        validation_id: Optional[str] = None,
        retryable: bool = True,
    ) -> PatchGenerationResult:
        """
        Execute automated patch generation for a vulnerability finding.

        :param vulnerability: Prioritized VulnerabilityFinding instance.
        :param risk_assessment: Optional RiskAssessment record.
        :param repository_context: Extracted RepositoryContext payload.
        :param attempt_number: Iteration number for this patch candidate (default 1).
        :param feedback: Optional failure feedback from previous validation attempt.
        :param persist: Whether to save the patch attempt record to the database.
        :param db_session: Optional active SQLAlchemy session.
        :param parent_patch_id: Optional ID of the parent patch attempt if this is a retry.
        :param retry_reason: Optional explanation of why the retry was triggered.
        :param validation_id: Optional ID of the validation result that triggered this retry.
        :param retryable: Whether this patch candidate is retryable.
        :return: PatchGenerationResult model.
        """
        start_now = utc_now()
        patch_id = f"PATCH-{hashlib.sha256(f'{vulnerability.id}:{attempt_number}:{start_now.isoformat()}'.encode('utf-8')).hexdigest()[:8].upper()}"

        logger.info(
            "Starting patch generation for %s (Attempt #%d, Workflow: %s)",
            vulnerability.id,
            attempt_number,
            vulnerability.workflow_id or "N/A",
        )

        warnings: list[str] = []

        # 1. Precondition: Risk Gating Check
        if (
            vulnerability.status not in (VulnerabilityStatus.ASSESSED, VulnerabilityStatus.PRIORITIZED)
            and risk_assessment is None
        ):
            msg = f"risk_gating_failed: Vulnerability '{vulnerability.id}' has not undergone risk assessment."
            logger.warning(msg)
            return self._build_failed_result(
                patch_id=patch_id,
                vulnerability=vulnerability,
                attempt_number=attempt_number,
                feedback=feedback,
                warnings=[msg],
                persist=persist,
                db_session=db_session,
                parent_patch_id=parent_patch_id,
                retry_reason=retry_reason,
                validation_id=validation_id,
                retryable=retryable,
            )

        # 2. Precondition: Repository Context Check
        if repository_context is None or not repository_context.surrounding_code:
            msg = f"missing_context: Insufficient repository context available for '{vulnerability.id}'."
            logger.warning(msg)
            return self._build_failed_result(
                patch_id=patch_id,
                vulnerability=vulnerability,
                attempt_number=attempt_number,
                feedback=feedback,
                warnings=[msg],
                persist=persist,
                db_session=db_session,
                parent_patch_id=parent_patch_id,
                retry_reason=retry_reason,
                validation_id=validation_id,
                retryable=retryable,
            )

        if any("path_outside_repository" in w or "Path traversal" in w for w in repository_context.warnings):
            msg = "fatal_path_security: Target file resides outside repository boundary."
            logger.warning(msg)
            return self._build_failed_result(
                patch_id=patch_id,
                vulnerability=vulnerability,
                attempt_number=attempt_number,
                feedback=feedback,
                warnings=[msg],
                persist=persist,
                db_session=db_session,
                parent_patch_id=parent_patch_id,
                retry_reason=retry_reason,
                validation_id=validation_id,
                retryable=retryable,
            )

        # 3. Precondition: LLM Service Config Check
        if not self.llm_service.is_configured:
            msg = "llm_unconfigured: LLM service is not configured. Set OPENAI_API_KEY."
            logger.warning(msg)
            return self._build_failed_result(
                patch_id=patch_id,
                vulnerability=vulnerability,
                attempt_number=attempt_number,
                feedback=feedback,
                warnings=[msg],
                persist=persist,
                db_session=db_session,
                parent_patch_id=parent_patch_id,
                retry_reason=retry_reason,
                validation_id=validation_id,
                retryable=retryable,
            )

        # 4. Construct Prompt
        system_prompt = self._load_prompt_template()
        user_prompt = self._format_user_prompt(
            vulnerability=vulnerability,
            risk_assessment=risk_assessment,
            context=repository_context,
            attempt_number=attempt_number,
            feedback=feedback,
        )

        # 5. Invoke LLM Service with Schema Validation
        llm_output: Optional[LLMPatchGeneration] = None
        try:
            llm_output = self.llm_service.generate_structured(
                prompt=user_prompt,
                system_prompt=system_prompt,
                response_schema=LLMPatchGeneration,
                temperature=0.1,
            )
        except Exception as e:
            logger.error("LLM patch generation raised exception: %s", e)
            warnings.append(f"llm_error: {str(e)}")

        if not llm_output or not isinstance(llm_output, LLMPatchGeneration):
            msg = "llm_generation_failed: Model failed to produce a valid structured patch response."
            logger.warning(msg)
            warnings.append(msg)
            return self._build_failed_result(
                patch_id=patch_id,
                vulnerability=vulnerability,
                attempt_number=attempt_number,
                feedback=feedback,
                warnings=warnings,
                persist=persist,
                db_session=db_session,
                parent_patch_id=parent_patch_id,
                retry_reason=retry_reason,
                validation_id=validation_id,
                retryable=retryable,
            )

        # 6. Compute Unified Diff
        unified_diff = llm_output.unified_diff or ""
        if not unified_diff and llm_output.changes:
            source_content = repository_context.surrounding_code
            window_start = repository_context.context_window_start or 1
            if repository_context.repository_root and repository_context.vulnerable_file:
                target_p = Path(repository_context.repository_root) / repository_context.vulnerable_file
                if target_p.exists() and target_p.is_file():
                    try:
                        source_content = target_p.read_text(encoding="utf-8")
                        window_start = 1
                    except Exception as e:
                        logger.warning("Could not read full source file for diff: %s", e)

            # Synthesize diff from code change blocks
            computed_diff, diff_warns = self._generate_unified_diff(
                file_path=repository_context.vulnerable_file,
                original_source=source_content,
                changes=llm_output.changes,
                context_window_start=window_start,
            )
            unified_diff = computed_diff
            warnings.extend(diff_warns)

        # 7. Validate Patch Safety & Constraints
        is_safe, safety_warnings = self._validate_patch_safety(
            context=repository_context,
            llm_patch=llm_output,
            unified_diff=unified_diff,
        )
        warnings.extend(safety_warnings)

        patch_status = PatchStatus.GENERATED if is_safe else PatchStatus.REJECTED

        # Convert changes to PatchFileChange models
        domain_changes = [
            PatchFileChange(
                file_path=c.file_path,
                start_line=c.start_line,
                end_line=c.end_line,
                original_code=c.original_code,
                replacement_code=c.replacement_code,
            )
            for c in llm_output.changes
        ]

        changed_files = list({c.file_path for c in llm_output.changes}) or [repository_context.vulnerable_file]

        orig_code = llm_output.changes[0].original_code if llm_output.changes else None
        prop_code = llm_output.changes[0].replacement_code if llm_output.changes else None

        model_name = self.llm_service.provider.model if self.llm_service.provider else None
        provider_name = self.llm_service.provider.name if self.llm_service.provider else None

        result = PatchGenerationResult(
            id=patch_id,
            workflow_id=vulnerability.workflow_id,
            vulnerability_id=vulnerability.id,
            attempt_number=attempt_number,
            status=patch_status,
            explanation=llm_output.explanation,
            unified_diff=unified_diff,
            changed_files=changed_files,
            changes=domain_changes,
            original_code=orig_code,
            proposed_code=prop_code,
            confidence=0.9 if is_safe else 0.0,
            model=model_name,
            provider=provider_name,
            feedback=feedback,
            assumptions=llm_output.assumptions,
            tests_to_run=llm_output.tests_to_run,
            warnings=warnings,
            generated_at=start_now,
            parent_patch_id=parent_patch_id,
            retry_reason=retry_reason,
            validation_id=validation_id,
            retryable=retryable,
        )

        # 8. Persist Patch Attempt to Database
        if persist:
            self._persist_patch_attempt(result, db_session=db_session)

        logger.info(
            "Patch generation finished for %s (Patch: %s, Status: %s, Changes: %d files)",
            vulnerability.id,
            patch_id,
            patch_status.value,
            len(changed_files),
        )

        return result

    def _build_failed_result(
        self,
        patch_id: str,
        vulnerability: VulnerabilityFinding,
        attempt_number: int,
        feedback: Optional[str],
        warnings: list[str],
        persist: bool = True,
        db_session: Optional[Any] = None,
        parent_patch_id: Optional[str] = None,
        retry_reason: Optional[str] = None,
        validation_id: Optional[str] = None,
        retryable: bool = True,
    ) -> PatchGenerationResult:
        """Construct and optionally persist a failed patch generation result."""
        result = PatchGenerationResult(
            id=patch_id,
            workflow_id=vulnerability.workflow_id,
            vulnerability_id=vulnerability.id,
            attempt_number=attempt_number,
            status=PatchStatus.FAILED,
            explanation=f"Patch generation failed: {'; '.join(warnings)}",
            unified_diff="",
            changed_files=[],
            changes=[],
            confidence=0.0,
            feedback=feedback,
            warnings=warnings,
            generated_at=utc_now(),
            parent_patch_id=parent_patch_id,
            retry_reason=retry_reason,
            validation_id=validation_id,
            retryable=retryable,
        )

        if persist:
            self._persist_patch_attempt(result, db_session=db_session)

        return result

    def _execute_in_session(self, db_session: Optional[Any], fn) -> None:
        """Execute database mutation within caller's session or a new scoped session."""
        if db_session is not None:
            fn(db_session)
            db_session.commit()
        else:
            with session_scope() as session:
                fn(session)

    def _persist_patch_attempt(
        self,
        result: PatchGenerationResult,
        db_session: Optional[Any] = None,
    ) -> None:
        """Save patch attempt record into SQLite database without mutating original source."""
        def _do(session):
            model_record = PatchAttemptModel(
                id=result.id,
                workflow_id=result.workflow_id,
                vulnerability_id=result.vulnerability_id,
                attempt_number=result.attempt_number,
                parent_patch_id=result.parent_patch_id,
                retry_reason=result.retry_reason,
                validation_id=result.validation_id,
                retryable=result.retryable,
                patch_format="unified_diff",
                patch_content=result.unified_diff,
                explanation=result.explanation,
                files_changed=json.dumps(result.changed_files),
                generation_model=result.model,
                generation_metadata=json.dumps({
                    "provider": result.provider,
                    "confidence": result.confidence,
                    "assumptions": result.assumptions,
                    "tests_to_run": result.tests_to_run,
                    "warnings": result.warnings,
                }),
                status=result.status.value,
                created_at=result.generated_at,
            )
            session.add(model_record)

            # Optionally update workflow stage
            if result.workflow_id:
                wf = session.query(WorkflowModel).filter(WorkflowModel.id == result.workflow_id).first()
                if wf and wf.status != WorkflowStatus.FAILED.value:
                    wf.current_stage = "PATCH_GENERATION_COMPLETE"

        self._execute_in_session(db_session, _do)

    def generate_patch_for_vulnerability_id(
        self,
        vulnerability_id: str,
        attempt_number: int = 1,
        feedback: Optional[str] = None,
        persist: bool = True,
        db_session: Optional[Any] = None,
        parent_patch_id: Optional[str] = None,
        retry_reason: Optional[str] = None,
        validation_id: Optional[str] = None,
        retryable: bool = True,
    ) -> PatchGenerationResult:
        """
        Convenience method to load finding, risk assessment, and repository context from database
        and trigger candidate patch generation.
        """
        finding: Optional[VulnerabilityFinding] = None
        risk_assessment: Optional[RiskAssessment] = None
        repo_path: Optional[str] = None

        def _fetch(session):
            nonlocal finding, risk_assessment, repo_path
            vuln_rec = session.query(VulnerabilityModel).filter(
                VulnerabilityModel.id == vulnerability_id
            ).first()

            if not vuln_rec:
                raise ValueError(f"Vulnerability '{vulnerability_id}' not found in database.")

            wf_rec = session.query(WorkflowModel).filter(
                WorkflowModel.id == vuln_rec.workflow_id
            ).first()

            if not wf_rec:
                raise ValueError(f"Workflow '{vuln_rec.workflow_id}' not found.")

            repo_path = wf_rec.repository_path
            raw_dict = vuln_rec.get_raw_finding()

            finding = VulnerabilityFinding(
                id=vuln_rec.id,
                workflow_id=vuln_rec.workflow_id,
                tool=vuln_rec.tool,
                rule_id=vuln_rec.rule_id,
                type=vuln_rec.type,
                cwe=vuln_rec.cwe,
                severity=Severity(vuln_rec.severity) if vuln_rec.severity in Severity.__members__ else Severity.MEDIUM,
                confidence=Confidence(vuln_rec.confidence) if vuln_rec.confidence and vuln_rec.confidence in Confidence.__members__ else None,
                file_path=vuln_rec.file_path,
                line_start=vuln_rec.line_start,
                line_end=vuln_rec.line_end,
                code_snippet=vuln_rec.code_snippet,
                description=vuln_rec.description,
                raw_finding=raw_dict,
                exploitability=vuln_rec.exploitability,
                business_impact=vuln_rec.business_impact,
                risk_score=vuln_rec.risk_score,
                priority=vuln_rec.priority,
                risk_reasoning=vuln_rec.risk_reasoning,
                status=VulnerabilityStatus(vuln_rec.status) if vuln_rec.status in VulnerabilityStatus.__members__ else VulnerabilityStatus.DETECTED,
                created_at=vuln_rec.created_at,
            )

            ra_rec = session.query(RiskAssessmentModel).filter(
                RiskAssessmentModel.vulnerability_id == vulnerability_id
            ).first()

            if ra_rec:
                risk_assessment = RiskAssessment(
                    id=ra_rec.id,
                    vulnerability_id=ra_rec.vulnerability_id,
                    workflow_id=ra_rec.workflow_id,
                    severity=Severity(ra_rec.severity) if ra_rec.severity in Severity.__members__ else Severity.MEDIUM,
                    severity_score=ra_rec.severity_score,
                    exploitability=ra_rec.exploitability,
                    business_impact=ra_rec.business_impact,
                    context_score=ra_rec.context_score or 0.0,
                    risk_score=ra_rec.risk_score,
                    priority=PriorityLevel(ra_rec.priority) if ra_rec.priority in PriorityLevel.__members__ else PriorityLevel.MEDIUM,
                    reasoning=ra_rec.reasoning,
                    assessment_method=AssessmentMethod(ra_rec.assessment_method) if ra_rec.assessment_method in AssessmentMethod.__members__ else AssessmentMethod.DETERMINISTIC_RULES,
                    model=ra_rec.model,
                    created_at=ra_rec.created_at,
                )

        if db_session is not None:
            _fetch(db_session)
        else:
            with session_scope() as session:
                _fetch(session)

        if not finding or not repo_path:
            raise ValueError(f"Could not load vulnerability finding for '{vulnerability_id}'.")

        # Extract repository context
        context = self.repository_context_service.build_context(
            repository_root=repo_path,
            finding=finding,
        )

        return self.generate_patch(
            vulnerability=finding,
            risk_assessment=risk_assessment,
            repository_context=context,
            attempt_number=attempt_number,
            feedback=feedback,
            persist=persist,
            db_session=db_session,
            parent_patch_id=parent_patch_id,
            retry_reason=retry_reason,
            validation_id=validation_id,
            retryable=retryable,
        )
