"""Unit tests for structural patch validation, diff safety constraints, and path security.

Tests representations and structural safety of candidate patches BEFORE isolated validation.
"""

from pathlib import Path
import pytest

from backend.agents.patch_generation_agent import PatchGenerationAgent
from backend.models.patch import PatchFileChange, PatchStatus
from backend.models.repository_context import ContextFile, RepositoryContext
from backend.services.llm.schemas import LLMCodeChange, LLMPatchGeneration


@pytest.fixture
def mock_context(tmp_path: Path) -> RepositoryContext:
    code = "def vulnerable_function():\n    return 42\n"
    file_p = tmp_path / "target.py"
    file_p.write_text(code, encoding="utf-8")

    return RepositoryContext(
        vulnerability_id="VULN-001",
        repository_root=str(tmp_path),
        vulnerable_file="target.py",
        line_start=1,
        line_end=2,
        language="python",
        code_snippet="return 42",
        surrounding_code=code,
        context_window_start=1,
        context_window_end=2,
        related_files=[
            ContextFile(file_path="helper.py", relationship="imported_by_target")
        ],
    )


# ==============================================================================
# 1. Structural Patch Diff Validation
# ==============================================================================

def test_valid_unified_diff_validation(mock_context: RepositoryContext):
    agent = PatchGenerationAgent()

    valid_diff = """--- a/target.py
+++ b/target.py
@@ -1,2 +1,2 @@
 def vulnerable_function():
-    return 42
+    return 100"""

    patch = LLMPatchGeneration(
        explanation="Safe replacement",
        changes=[
            LLMCodeChange(
                file_path="target.py",
                start_line=2,
                end_line=2,
                original_code="    return 42",
                replacement_code="    return 100",
            )
        ],
        unified_diff=valid_diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=valid_diff,
    )

    assert is_safe is True
    assert len(warnings) == 0


def test_empty_diff_rejected(mock_context: RepositoryContext):
    agent = PatchGenerationAgent()

    patch = LLMPatchGeneration(
        explanation="No changes made",
        changes=[],
        unified_diff="",
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff="",
    )

    assert is_safe is False
    assert any("empty_diff" in w for w in warnings)


def test_diff_without_identifiable_files_rejected(mock_context: RepositoryContext):
    agent = PatchGenerationAgent()

    malformed_diff = "@@ -1,2 +1,2 @@\n- old\n+ new"

    patch = LLMPatchGeneration(
        explanation="Malformed diff without headers",
        changes=[],
        unified_diff=malformed_diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=malformed_diff,
    )

    assert is_safe is False
    assert any("invalid_diff" in w for w in warnings)


# ==============================================================================
# 2. Path Traversal & Absolute Path Rejection
# ==============================================================================

@pytest.mark.parametrize(
    "bad_path",
    [
        "../../etc/passwd",
        "../secrets.env",
        "app/../../secret.py",
        "nested/../../../root.txt",
    ],
)
def test_path_traversal_detection_and_rejection(mock_context: RepositoryContext, bad_path: str):
    agent = PatchGenerationAgent()

    diff = f"--- a/{bad_path}\n+++ b/{bad_path}\n@@ -1,1 +1,1 @@\n-1\n+2"
    patch = LLMPatchGeneration(
        explanation="Traversal test",
        changes=[
            LLMCodeChange(
                file_path=bad_path,
                start_line=1,
                end_line=1,
                original_code="1",
                replacement_code="2",
            )
        ],
        unified_diff=diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=diff,
    )

    assert is_safe is False
    assert any("path_traversal_rejected" in w for w in warnings)


@pytest.mark.parametrize(
    "abs_path",
    [
        "/etc/shadow",
        "/var/log/syslog",
        "C:/Windows/System32/cmd.exe",
        "D:\\sensitive\\key.pem",
        "\\unc\\server\\share",
    ],
)
def test_absolute_path_detection_and_rejection(mock_context: RepositoryContext, abs_path: str):
    agent = PatchGenerationAgent()

    diff = f"--- a/{abs_path}\n+++ b/{abs_path}\n@@ -1,1 +1,1 @@\n-1\n+2"
    patch = LLMPatchGeneration(
        explanation="Absolute path test",
        changes=[
            LLMCodeChange(
                file_path=abs_path,
                start_line=1,
                end_line=1,
                original_code="1",
                replacement_code="2",
            )
        ],
        unified_diff=diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=diff,
    )

    assert is_safe is False
    assert any("absolute_path_rejected" in w or "unrelated_file_rejected" in w for w in warnings)


# ==============================================================================
# 3. Test File Modification Rejection
# ==============================================================================

@pytest.mark.parametrize(
    "test_file",
    [
        "tests/test_target.py",
        "tests/unit/test_security.py",
        "test_app.py",
        "app_test.py",
        "tests/conftest.py",
    ],
)
def test_test_file_modification_rejected(mock_context: RepositoryContext, test_file: str):
    agent = PatchGenerationAgent()

    diff = f"--- a/{test_file}\n+++ b/{test_file}\n@@ -1,1 +1,1 @@\n-assert False\n+assert True"
    patch = LLMPatchGeneration(
        explanation="Attempting to tamper with test",
        changes=[
            LLMCodeChange(
                file_path=test_file,
                start_line=1,
                end_line=1,
                original_code="assert False",
                replacement_code="assert True",
            )
        ],
        unified_diff=diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=diff,
    )

    assert is_safe is False
    assert any("test_modification_rejected" in w for w in warnings)


# ==============================================================================
# 4. Patch Scope & Size Boundary Enforcement
# ==============================================================================

def test_unrelated_file_rejection(mock_context: RepositoryContext):
    agent = PatchGenerationAgent()

    diff = "--- a/random_other_file.py\n+++ b/random_other_file.py\n@@ -1,1 +1,1 @@\n-a\n+b"
    patch = LLMPatchGeneration(
        explanation="Touching unrelated file",
        changes=[
            LLMCodeChange(
                file_path="random_other_file.py",
                start_line=1,
                end_line=1,
                original_code="a",
                replacement_code="b",
            )
        ],
        unified_diff=diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=diff,
    )

    assert is_safe is False
    assert any("unrelated_file_rejected" in w for w in warnings)


def test_allowed_related_file_acceptance(mock_context: RepositoryContext):
    agent = PatchGenerationAgent()

    diff = "--- a/helper.py\n+++ b/helper.py\n@@ -1,1 +1,1 @@\n-old_helper\n+new_helper"
    patch = LLMPatchGeneration(
        explanation="Updating related helper file",
        changes=[
            LLMCodeChange(
                file_path="helper.py",
                start_line=1,
                end_line=1,
                original_code="old_helper",
                replacement_code="new_helper",
            )
        ],
        unified_diff=diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=diff,
    )

    assert is_safe is True
    assert len(warnings) == 0


def test_patch_lines_limit_enforcement(mock_context: RepositoryContext):
    agent = PatchGenerationAgent(max_patch_lines=10)

    long_diff = "--- a/target.py\n+++ b/target.py\n" + ("+ line\n" * 15)
    patch = LLMPatchGeneration(
        explanation="Long patch",
        changes=[
            LLMCodeChange(
                file_path="target.py",
                start_line=1,
                end_line=1,
                original_code="x",
                replacement_code="x\n" * 15,
            )
        ],
        unified_diff=long_diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=long_diff,
    )

    assert is_safe is False
    assert any("diff_too_large" in w for w in warnings)


def test_patch_chars_limit_enforcement(mock_context: RepositoryContext):
    agent = PatchGenerationAgent(max_patch_chars=50)

    diff = "--- a/target.py\n+++ b/target.py\n@@ -1,1 +1,1 @@\n-1\n+" + ("a" * 100)
    patch = LLMPatchGeneration(
        explanation="Oversized char patch",
        changes=[
            LLMCodeChange(
                file_path="target.py",
                start_line=1,
                end_line=1,
                original_code="1",
                replacement_code="a" * 100,
            )
        ],
        unified_diff=diff,
    )

    is_safe, warnings = agent._validate_patch_safety(
        context=mock_context,
        llm_patch=patch,
        unified_diff=diff,
    )

    assert is_safe is False
    assert any("diff_chars_exceeded" in w for w in warnings)


# ==============================================================================
# 5. Programmatic Unified Diff Generation
# ==============================================================================

def test_programmatic_diff_generation():
    agent = PatchGenerationAgent()

    original_code = """import os

def run_task(cmd):
    return os.system(cmd)
"""
    changes = [
        LLMCodeChange(
            file_path="task.py",
            start_line=4,
            end_line=4,
            original_code="    return os.system(cmd)",
            replacement_code="    return subprocess.run(cmd, check=True)",
        )
    ]

    diff_str, warnings = agent._generate_unified_diff(
        file_path="task.py",
        original_source=original_code,
        changes=changes,
    )

    assert "--- a/task.py" in diff_str
    assert "+++ b/task.py" in diff_str
    assert "-    return os.system(cmd)" in diff_str
    assert "+    return subprocess.run(cmd, check=True)" in diff_str
    assert len(warnings) == 0
