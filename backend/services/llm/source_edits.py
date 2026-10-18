"""Source-bound edits for local models; paths and originals stay server-owned."""
import ast
import json
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from backend.models.repository_context import RepositoryContext
from backend.services.llm.schemas import LLMCodeChange, LLMPatchGeneration


class SourceEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    block_id: str
    replacement_code: str = Field(description="Complete replacement for the selected block, including its function definition and indentation")


class SourceEditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    explanation: str
    edits: list[SourceEdit] = Field(min_length=1, max_length=20)


@dataclass(frozen=True)
class SourceBlock:
    block_id: str
    file_path: str
    start_line: int
    end_line: int
    code: str


def source_blocks(context: RepositoryContext, line_budget: int) -> list[SourceBlock]:
    """Use only bounded, redacted context already supplied by context extraction."""
    blocks = []
    seen = set()
    snippets = [(context.vulnerable_file, context.context_window_start, context.surrounding_code)]
    snippets.extend((item.file_path, 1, item.content_snippet) for item in context.related_files)
    for path, first_line, snippet in snippets:
        normalized = path.replace("\\", "/")
        parts = normalized.lower().split("/")
        if (normalized in seen or parts[-1].startswith("test_") or parts[-1].endswith("_test.py")
                or any(part in {"test", "tests"} for part in parts[:-1])):
            continue
        seen.add(normalized)
        lines = snippet.splitlines()[:max(0, line_budget)]
        line_budget -= len(lines)
        if not lines:
            continue
        # Split complete top-level statements so a model can replace a function
        # without re-emitting unrelated imports or other functions.
        try:
            nodes = ast.parse("\n".join(lines)).body
            ranges = [(min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])]), node.end_lineno)
                      for node in nodes]
        except SyntaxError:
            ranges = [(1, len(lines))]
        for start, end in ranges:
            blocks.append(SourceBlock(f"source_{len(blocks) + 1}", normalized,
                                      first_line + start - 1, first_line + end - 1,
                                      "\n".join(lines[start - 1:end])))
    return blocks


def blocks_json(blocks: list[SourceBlock]) -> str:
    return json.dumps([{"block_id": block.block_id, "file_path": block.file_path,
                        "code": block.code} for block in blocks], indent=2)


def grounded_patch(response: SourceEditResponse, blocks: list[SourceBlock]) -> LLMPatchGeneration:
    """Reject invented/repeated IDs; preserve exact source coordinates and text."""
    indexed = {block.block_id: block for block in blocks}
    used = set()
    changes = []
    for edit in response.edits:
        if edit.block_id not in indexed or edit.block_id in used:
            raise ValueError("Unknown or repeated source block ID")
        used.add(edit.block_id)
        block = indexed[edit.block_id]
        changes.append(LLMCodeChange(file_path=block.file_path, start_line=block.start_line,
                                     end_line=block.end_line, original_code=block.code,
                                     replacement_code=edit.replacement_code))
    return LLMPatchGeneration(explanation=response.explanation, changes=changes, unified_diff="")
