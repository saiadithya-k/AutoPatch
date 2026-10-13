"""Regressions for inconclusive validation and deterministic edit safety."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.agents.retry_agent import RetryAgent
from backend.agents.validation_agent import ValidationAgent
from backend.models.validation import ValidationResult, ValidationStatus
from backend.models.patch import PatchStatus
from backend.models.repository_context import ContextFile, RepositoryContext
from backend.models.vulnerability import VulnerabilityFinding
from backend.services.llm.schemas import LLMCodeChange, LLMPatchGeneration
from backend.services.llm.mock_provider import MockLLMProvider
from backend.services.llm.service import LLMService
from backend.agents.scanning_agent import ScanningAgent
from backend.tools.bandit_runner import BanditRunner
from backend.tools.patch_applier import PatchApplier
from backend.tools.sandbox import DockerRequiredError, SandboxExecutionResult, get_default_sandbox_executor
from backend.tools.semgrep_runner import SemgrepRunner
from backend.tools.test_runner import TestResult


@pytest.mark.parametrize("status,complete", [("DEGRADED", False), ("FAILED", False), ("UNKNOWN", False), ("COMPLETED", False)])
def test_incomplete_scan_never_passes_or_mutates_database(tmp_path, status, complete):
    (tmp_path / "app.py").write_text("value = 1\n")
    scanner = MagicMock()
    scanner.scan.return_value = ([], {"scan_status": status, "coverage_complete": complete})
    runner = MagicMock()
    runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=[], tests_run=1)
    finding = VulnerabilityFinding(id="v1", tool="bandit", type="unsafe", file_path="app.py", description="unsafe", status="PRIORITIZED")
    agent = ValidationAgent(test_runner=runner, scanning_agent=scanner)
    with patch.object(agent, "_run_syntax_check", return_value=(True, "ok")), \
         patch.object(agent, "_update_patch_status") as update, \
         patch("backend.agents.validation_agent.session_scope", side_effect=AssertionError("Unexpected DB write")):
        result = agent.execute_validation("p1", finding,
            "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n", tmp_path, persist=False)
    assert result.status == ValidationStatus.ERROR
    assert not result.security_scan_passed
    assert not result.original_vulnerability_resolved
    assert result.failure_category == "INFRASTRUCTURE_FAILURE"
    update.assert_not_called()
    assert (tmp_path / "app.py").read_text() == "value = 1\n"


def test_local_fallback_policy_is_enforced():
    settings = MagicMock(DOCKER_ENABLED=False, ALLOW_LOCAL_FALLBACK=False)
    with patch("backend.tools.sandbox.get_settings", return_value=settings), pytest.raises(DockerRequiredError):
        get_default_sandbox_executor()


@pytest.mark.parametrize("runner_class", [BanditRunner, SemgrepRunner])
def test_security_scanners_execute_through_docker_executor(tmp_path, runner_class):
    sandbox = MagicMock()
    sandbox.sandbox_type = "docker"
    sandbox.run_command.return_value = SandboxExecutionResult(0, json.dumps({"results": [], "errors": []}), "", 0.01)
    with patch("subprocess.run", side_effect=AssertionError("Host execution bypassed sandbox")):
        result = runner_class(sandbox=sandbox).run(tmp_path)
    assert result.success
    command = sandbox.run_command.call_args.args[0]
    assert command[0] == ("python" if runner_class is BanditRunner else "pysemgrep")
    assert str(tmp_path) not in command
    assert sandbox.run_command.call_args.kwargs["cwd"] == tmp_path


@pytest.mark.parametrize("stdout,exit_code", [("", 0), ('{"results":[],"errors":[]}', 2), ('{"results":[],"errors":[{"message":"parse failed"}]}', 0)])
def test_semgrep_incomplete_output_fails_closed(tmp_path, stdout, exit_code):
    sandbox = MagicMock(sandbox_type="docker")
    sandbox.run_command.return_value = SandboxExecutionResult(exit_code, stdout, "", .01)
    assert not SemgrepRunner(sandbox=sandbox).run(tmp_path).success


def test_multiple_replacements_preserve_original_coordinates(tmp_path):
    original = "a = 1\nb = 2\nc = 3\n"
    (tmp_path / "app.py").write_text(original)
    changes = [LLMCodeChange(file_path="app.py", start_line=1, end_line=1, original_code="a = 1", replacement_code="a = 10\na2 = 11"),
               LLMCodeChange(file_path="app.py", start_line=3, end_line=3, original_code="c = 3", replacement_code="c = 30")]
    diff, warnings = PatchGenerationAgent()._generate_unified_diff("app.py", original, changes)
    assert not warnings
    success, reason = PatchApplier().apply_patch(tmp_path, diff)
    assert success, reason
    assert (tmp_path / "app.py").read_text() == "a = 10\na2 = 11\nb = 2\nc = 30\n"


def test_ambiguous_and_overlapping_replacements_are_rejected():
    agent = PatchGenerationAgent()
    repeated = LLMCodeChange(file_path="app.py", start_line=99, end_line=99, original_code="x = 1", replacement_code="x = 2")
    assert not agent._generate_unified_diff("app.py", "x = 1\nx = 1\n", [repeated])[0]
    overlapping = LLMCodeChange(file_path="app.py", start_line=1, end_line=1, original_code="x = 1", replacement_code="x = 2")
    assert not agent._generate_unified_diff("app.py", "x = 1\n", [overlapping, overlapping])[0]


@pytest.mark.parametrize("constructor_limit,override,used,expected", [(0, 2, 0, True), (3, 0, 0, False), (3, 1, 1, False)])
def test_retry_policy_uses_effective_override(constructor_limit, override, used, expected):
    agent = RetryAgent(max_retries=constructor_limit)
    validation = ValidationResult(id="v", patch_attempt_id="p", vulnerability_id="f", status=ValidationStatus.FAILED, failure_category="SYNTAX_ERROR")
    assert agent.evaluate_retryability(validation, used, max_retries=override).should_retry is expected


def context_for(tmp_path):
    return RepositoryContext(vulnerability_id="v1", repository_root=str(tmp_path), vulnerable_file="app.py",
        line_start=1, line_end=1, surrounding_code="value = 1\n", context_window_start=1, context_window_end=1,
        related_files=[ContextFile(file_path="helper.py")])


def test_multifile_generation_uses_each_files_own_source(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n")
    (tmp_path / "helper.py").write_text("other = 3\n")
    changes = [LLMCodeChange(file_path="app.py", start_line=1, end_line=1, original_code="value = 1", replacement_code="value = 2"),
               LLMCodeChange(file_path="helper.py", start_line=1, end_line=1, original_code="other = 3", replacement_code="other = 4")]
    output = LLMPatchGeneration(explanation="Fix related sources", changes=changes)
    agent = PatchGenerationAgent(llm_service=LLMService(provider=MockLLMProvider(canned_parsed=output)))
    finding = VulnerabilityFinding(id="v1", tool="bandit", type="unsafe", file_path="app.py", description="unsafe", status="PRIORITIZED")
    result = agent.generate_patch(finding, None, context_for(tmp_path), persist=False)
    assert result.status == PatchStatus.GENERATED
    assert result.changed_files == ["app.py", "helper.py"]
    assert (tmp_path / "app.py").read_text() == "value = 1\n"
    assert (tmp_path / "helper.py").read_text() == "other = 3\n"
    success, reason = PatchApplier().apply_patch(tmp_path, result.unified_diff)
    assert success, reason
    assert (tmp_path / "app.py").read_text() == "value = 2\n"
    assert (tmp_path / "helper.py").read_text() == "other = 4\n"


@pytest.mark.parametrize("directive", ["nosec B605", "nosemgrep", "nosem"])
def test_scanner_suppression_is_rejected(tmp_path, directive):
    output = LLMPatchGeneration(explanation="Suppress warning", changes=[],
        unified_diff=f"--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = eval(user)\n+value = eval(user)  # {directive}\n")
    safe, warnings = PatchGenerationAgent()._validate_patch_safety(context_for(tmp_path), output, output.unified_diff)
    assert not safe
    assert "scanner_suppression_rejected" in warnings[0]


def test_remaining_single_scanner_identity_survives_merged_provenance():
    scan = ScanningAgent()
    bandit = VulnerabilityFinding(id="b", tool="bandit", rule_id="B307", type="eval", cwe="CWE-95", file_path="app.py", line_start=3, description="eval")
    semgrep = VulnerabilityFinding(id="s", tool="semgrep", rule_id="dynamic-eval", type="eval", cwe="CWE-95", file_path="app.py", line_start=3, description="eval")
    merged = scan._deduplicate_findings([bandit, semgrep])[0]
    # The original scanner composition changed; the vulnerability remains.
    comparison = ValidationAgent()._compare_security_findings(merged, [merged], [semgrep])
    assert not comparison.original_vulnerability_resolved
    assert comparison.remaining_original_findings_count == 1


def test_all_skipped_tests_do_not_pass(tmp_path):
    sandbox = MagicMock(sandbox_type="local_workspace_dev_fallback")
    sandbox.run_command.return_value = SandboxExecutionResult(0, "2 skipped in 0.01s", "", .01)
    from backend.tools.test_runner import TestRunner
    result = TestRunner(sandbox=sandbox).run_tests(tmp_path)
    assert not result.success
    assert result.tests_run == 0


def test_hashes_include_hidden_sources_under_hidden_ancestor(tmp_path):
    root = tmp_path / ".hidden-parent" / "repository"
    root.mkdir(parents=True)
    (root / ".config.py").write_text("value = 1\n")
    assert ".config.py" in ValidationAgent._calculate_repo_hashes(root)


def test_generation_and_application_handle_source_without_final_newline(tmp_path):
    (tmp_path / "app.py").write_text("value = 1")
    change = LLMCodeChange(file_path="app.py", start_line=1, end_line=1, original_code="value = 1", replacement_code="value = 2")
    diff, warnings = PatchGenerationAgent()._generate_unified_diff("app.py", "value = 1", [change])
    assert not warnings
    success, reason = PatchApplier().apply_patch(tmp_path, diff, strict_counts=True)
    assert success, reason
    assert (tmp_path / "app.py").read_text() == "value = 2\n"


@pytest.mark.parametrize("excluded_ancestor", [".test-artifacts", ".test-tmp", ".venv-runtime"])
@pytest.mark.parametrize("runner_class", [BanditRunner, SemgrepRunner])
def test_explicit_repository_is_scanned_under_excluded_named_ancestor(tmp_path, excluded_ancestor, runner_class):
    repository = tmp_path / excluded_ancestor / "submitted-repository"
    repository.mkdir(parents=True)
    (repository / "app.py").write_text("import os\nos.system(input())\n")
    result = runner_class().run(repository)
    assert result.success, result.error_message
    assert result.findings, "The submitted repository must not be excluded because of its parent directory."
