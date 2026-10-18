"""Local-model edits cannot invent paths, rewrite tests, or drift from originals."""
import json

import pytest
from pydantic import ValidationError

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.models.repository_context import ContextFile, RelatedTest, RepositoryContext
from backend.models.vulnerability import VulnerabilityFinding
from backend.services.llm.mock_provider import MockLLMProvider
from backend.services.llm.service import LLMService
from backend.services.llm.source_edits import SourceEditResponse, grounded_patch, source_blocks


def context_for(tmp_path, source="def parse(raw):\n    return eval(raw)"):
    (tmp_path / "app.py").write_text(source + "\n", encoding="utf-8")
    return RepositoryContext(vulnerability_id="v", repository_root=str(tmp_path), vulnerable_file="app.py",
                             line_start=2, line_end=2, surrounding_code=source,
                             context_window_start=1, context_window_end=len(source.splitlines()))


def response_for(block_id="source_1", **extra):
    return SourceEditResponse.model_validate({"explanation": "Parse literals safely", "edits": [
        {"block_id": block_id, "replacement_code": "def parse(raw):\n    import ast\n    return ast.literal_eval(raw)", **extra}]})


def test_anchor_preserves_decorators_and_window_coordinates(tmp_path):
    context = context_for(tmp_path, "@cached\ndef parse(raw):\n    return eval(raw)")
    context.context_window_start = 15
    blocks = source_blocks(context, 20)
    patch = grounded_patch(response_for(), blocks)
    assert patch.changes[0].start_line == 15
    assert patch.changes[0].end_line == 17
    assert patch.changes[0].original_code == context.surrounding_code


@pytest.mark.parametrize("path", ["test_other.py", "other_test.py", "tests/helper.py", "test/helper.py"])
def test_behavior_tests_never_become_editable(tmp_path, path):
    context = context_for(tmp_path)
    context.related_files = [ContextFile(file_path=path, content_snippet="def test_behavior():\n    pass")]
    assert [block.file_path for block in source_blocks(context, 50)] == ["app.py"]


def test_total_source_budget_is_bounded_and_paths_are_deduplicated(tmp_path):
    context = context_for(tmp_path)
    context.related_files = [ContextFile(file_path="app.py", content_snippet="duplicate = 1"),
                             ContextFile(file_path="caller.py", content_snippet="one = 1\ntwo = 2\nthree = 3")]
    blocks = source_blocks(context, 4)
    assert sum(len(block.code.splitlines()) for block in blocks) == 4
    assert len({(block.file_path, block.start_line) for block in blocks}) == len(blocks)


def test_invented_and_duplicate_block_ids_are_rejected(tmp_path):
    blocks = source_blocks(context_for(tmp_path), 20)
    with pytest.raises(ValueError, match="Unknown or repeated"):
        grounded_patch(response_for("../../outside.py"), blocks)
    duplicate = response_for()
    duplicate.edits.append(duplicate.edits[0])
    with pytest.raises(ValueError, match="Unknown or repeated"):
        grounded_patch(duplicate, blocks)
    with pytest.raises(ValidationError):
        response_for(file_path="outside.py")


class ScriptedLocalProvider(MockLLMProvider):
    @property
    def name(self):
        return "ollama"


def generate(context, response, **kwargs):
    provider = ScriptedLocalProvider(canned_parsed=response)
    agent = PatchGenerationAgent(llm_service=LLMService(provider=provider))
    finding = VulnerabilityFinding(id="v", type="unsafe evaluation", tool="bandit", file_path="app.py",
                                   description="unsafe evaluation", status="ASSESSED")
    result = agent.generate_patch(finding, repository_context=context, persist=False, **kwargs)
    return result, provider


def test_retry_uses_original_source_even_when_failed_candidate_has_different_text(tmp_path):
    context = context_for(tmp_path)
    result, provider = generate(context, response_for(), attempt_number=2,
                                feedback="The failed candidate used json.loads(raw), which rejects Python literals.")
    assert result.status.value == "GENERATED"
    assert result.changes[0].original_code == context.surrounding_code
    assert "-    return eval(raw)" in result.unified_diff
    prompt = provider.call_history[0][-1].content
    assert prompt.index("json.loads") < prompt.index("<original_editable_source>")
    assert (tmp_path / "app.py").read_text() == context.surrounding_code + "\n"


def test_source_changed_after_extraction_fails_closed(tmp_path):
    context = context_for(tmp_path)
    (tmp_path / "app.py").write_text("def parse(raw):\n    return raw\n")
    result, _ = generate(context, response_for())
    assert result.status.value == "REJECTED"
    assert not result.unified_diff
    assert "return raw" in (tmp_path / "app.py").read_text()


def test_unknown_block_response_is_failed_generation(tmp_path):
    result, _ = generate(context_for(tmp_path), response_for("invented"))
    assert result.status.value == "FAILED"
    assert not result.unified_diff


def test_model_cannot_override_original_or_destination_fields():
    with pytest.raises(ValidationError):
        SourceEditResponse.model_validate({"explanation": "unsafe", "edits": [
            {"block_id": "source_1", "replacement_code": "pass", "original_code": "invented"}]})


def test_related_caller_can_be_changed_in_same_candidate(tmp_path):
    context = context_for(tmp_path)
    context.related_files = [ContextFile(file_path="caller.py", content_snippet="def call(raw):\n    return parse(raw)")]
    blocks = source_blocks(context, 20)
    response = response_for()
    response.edits.append(response.edits[0].model_copy(update={"block_id": "source_2", "replacement_code": "def call(raw):\n    return parse(raw.strip())"}))
    patch = grounded_patch(response, blocks)
    assert [change.file_path for change in patch.changes] == ["app.py", "caller.py"]


def test_test_context_is_read_only_and_total_prompt_code_is_bounded(tmp_path):
    context = context_for(tmp_path)
    context.related_tests = [RelatedTest(file_path="test_app.py", content_snippet="\n".join(f"# line {index}" for index in range(600)))]
    _, provider = generate(context, response_for())
    prompt = provider.call_history[0][-1].content
    assert "# line 497" in prompt
    assert "# line 498" not in prompt
    editable = json.loads(prompt.split("<original_editable_source>\n", 1)[1].split("\n</original_editable_source>", 1)[0])
    assert all(block["file_path"] != "test_app.py" for block in editable)
