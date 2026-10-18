"""Failures exposed by broader model acceptance must retain reliable evidence."""
import json
from unittest.mock import MagicMock

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.agents.retry_agent import RetryAgent
from backend.agents.validation_agent import ValidationAgent
from backend.database.models import PatchAttemptModel, ReviewDecisionModel, ValidationResultModel, WorkflowModel, VulnerabilityModel
from backend.models.vulnerability import VulnerabilityFinding
from backend.services.llm.service import LLMService
from backend.services.repository_context import RepositoryContextService
from backend.tools.test_runner import TestResult


def test_new_scanner_finding_is_persisted_as_failure_not_serialization_error(tmp_path, db_session):
    (tmp_path / "app.py").write_text("value = 1\n")
    db_session.add(WorkflowModel(id="w", repository_path=str(tmp_path)))
    db_session.add(VulnerabilityModel(id="v", workflow_id="w", tool="bandit", type="unsafe", severity="HIGH", file_path="app.py", description="unsafe"))
    db_session.add(PatchAttemptModel(id="p", workflow_id="w", vulnerability_id="v", patch_content="diff", status="GENERATED"))
    db_session.commit()
    original = VulnerabilityFinding(id="v", tool="bandit", rule_id="B605", type="unsafe", severity="HIGH", file_path="app.py", description="unsafe")
    new = VulnerabilityFinding(id="new", tool="bandit", rule_id="B603", type="new unsafe call", severity="HIGH", file_path="other.py", description="new risk")
    scanner = MagicMock()
    scanner.scan.return_value = ([new], {"scan_status": "COMPLETED", "coverage_complete": True})
    tests = MagicMock()
    tests.run_tests.return_value = TestResult(success=True, exit_code=0, command=[], tests_run=1, tests_passed=1)
    agent = ValidationAgent(scanning_agent=scanner, test_runner=tests)
    agent._run_syntax_check = MagicMock(return_value=(True, "ok"))
    result = agent.execute_validation("p", original, "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n", tmp_path, workflow_id="w", persist=True, db_session=db_session)
    assert result.status.value == "FAILED"
    assert result.failure_category == "NEW_VULNERABILITY"
    stored = db_session.get(ValidationResultModel, result.id)
    evidence = json.loads(stored.new_findings)
    assert evidence[0]["id"] == "new"
    assert isinstance(evidence[0]["created_at"], str)


def test_generation_rejection_is_not_mistaken_for_a_human_decision(db_session):
    db_session.add(PatchAttemptModel(id="generated-reject", vulnerability_id="v", status="REJECTED", patch_content=""))
    db_session.commit()
    validator = MagicMock()
    result = RetryAgent(validation_agent=validator).run_retry_loop("generated-reject", db_session=db_session)
    assert result.status == "FAILED"
    assert "generation failed or was rejected" in result.final_failure_reason
    validator.validate_patch.assert_not_called()


def test_human_rejection_still_blocks_retry(db_session):
    import pytest
    from backend.agents.validation_agent import PatchLifecycleConflict
    db_session.add(PatchAttemptModel(id="human-reject", vulnerability_id="v", status="REJECTED", patch_content="diff"))
    db_session.add(ReviewDecisionModel(id="review", patch_attempt_id="human-reject", decision="REJECTED", reviewer_label="Developer"))
    db_session.commit()
    with pytest.raises(PatchLifecycleConflict):
        RetryAgent().run_retry_loop("human-reject", db_session=db_session)


def test_model_receives_redacted_caller_and_behavior_test_snippets(tmp_path):
    secret = "sk-" + "x" * 30
    (tmp_path / "query_builder.py").write_text("def build_query(name):\n    return name\n")
    (tmp_path / "app.py").write_text(f"from query_builder import build_query\nAPI_KEY = '{secret}'\ndef lookup(name):\n    return build_query(name)\n")
    (tmp_path / "test_app.py").write_text("def test_lookup_preserves_contract():\n    pass\n")
    finding = VulnerabilityFinding(id="v", tool="bandit", type="unsafe", file_path="query_builder.py", line_start=2, description="unsafe")
    service = RepositoryContextService()
    context = service.build_context(str(tmp_path), finding)
    assert any(test.file_path == "test_app.py" for test in context.related_tests)
    agent = PatchGenerationAgent(llm_service=LLMService(provider=None), repository_context_service=service)
    prompt = agent._format_user_prompt(finding, None, context, feedback="Previous candidate failed")
    assert "return build_query(name)" in prompt
    assert "def test_lookup_preserves_contract" in prompt
    assert secret not in prompt
    assert "NEVER applied to the original repository" in prompt


def test_ollama_metadata_and_client_validation_preserve_json_mode():
    from backend.services.llm.openai_provider import OpenAIProvider
    from backend.services.llm.schemas import LLMPatchGeneration
    local = OpenAIProvider(api_key="local", provider_name="ollama")
    payload = local._prepare_payload([], response_schema=LLMPatchGeneration)
    assert local.name == "ollama"
    assert payload["response_format"] == {"type": "json_object"}
    schema = LLMPatchGeneration.model_json_schema()
    assert schema["$defs"]["LLMCodeChange"]["properties"]["original_code"]["minLength"] == 1
    cloud = OpenAIProvider(api_key="unit-test")
    assert cloud._prepare_payload([], response_schema=LLMPatchGeneration)["response_format"] == {"type": "json_object"}


def test_docker_interrupt_removes_container_before_propagating(tmp_path):
    import pytest
    from unittest.mock import patch
    from backend.tools.sandbox import DockerSandboxExecutor
    with patch.object(DockerSandboxExecutor, "is_docker_available", return_value=True), \
         patch("backend.tools.sandbox.subprocess.run", side_effect=[KeyboardInterrupt(), MagicMock(returncode=0)]) as run:
        with pytest.raises(KeyboardInterrupt):
            DockerSandboxExecutor().run_command(["python", "-c", "pass"], tmp_path)
    cleanup = run.call_args_list[-1].args[0]
    assert cleanup[:3] == ["docker", "rm", "-f"]
    assert cleanup[3].startswith("autopatch_val_")


def test_structured_requests_bound_model_output(monkeypatch):
    from backend.config import get_settings
    from backend.services.llm.mock_provider import MockLLMProvider
    from backend.services.llm.schemas import LLMPatchGeneration
    from unittest.mock import patch
    provider = MockLLMProvider()
    monkeypatch.setattr(get_settings(), "LLM_MAX_OUTPUT_TOKENS", 2048)
    with patch.object(provider, "generate_text", wraps=provider.generate_text) as generate:
        assert LLMService(provider=provider).generate_structured("patch", response_schema=LLMPatchGeneration)
    assert generate.call_args.kwargs["max_tokens"] == 2048


def test_acceptance_cli_preserves_interrupted_evidence(tmp_path, db_session):
    from unittest.mock import patch
    from scripts.acceptance_cases import SQL
    from scripts.run_acceptance import execute_case
    with patch("backend.services.workflows.WorkflowRunner.run", side_effect=KeyboardInterrupt()):
        result = execute_case(SQL, tmp_path / "repository", db_session, handle_interrupt=True)
    assert result["interrupted"]
    assert not result["passed"]
    assert result["source_unchanged"]
    assert result["report"]["workflow"]["outcome"] == "INTERRUPTED"
