"""Unit tests for pure-Python PatchApplier tool.

Verifies unified diff parsing, accurate hunk application, path validation,
traversal rejection, and graceful error handling without modifying outside files.
"""

from pathlib import Path
import pytest

from backend.tools.patch_applier import PatchApplicationError, PatchApplier


def test_patch_applier_successful_single_hunk(tmp_path: Path):
    """Verify clean patch application on target file in workspace."""
    app_file = tmp_path / "app.py"
    app_file.write_text("def hello():\n    return 'insecure'\n", encoding="utf-8")

    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def hello():
-    return 'insecure'
+    return 'secure'"""

    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is True
    assert err is None

    new_content = app_file.read_text(encoding="utf-8")
    assert "return 'secure'" in new_content
    assert "return 'insecure'" not in new_content


def test_patch_applier_multi_line_replacement(tmp_path: Path):
    """Verify multi-line addition and deletion."""
    app_file = tmp_path / "calc.py"
    orig = "import os\n\ndef run(cmd):\n    os.system(cmd)\n    return 0\n"
    app_file.write_text(orig, encoding="utf-8")

    diff = """--- a/calc.py
+++ b/calc.py
@@ -3,3 +3,3 @@
 def run(cmd):
-    os.system(cmd)
-    return 0
+    return subprocess.run(cmd, check=True)"""

    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is True
    assert err is None

    new_content = app_file.read_text(encoding="utf-8")
    assert "subprocess.run(cmd, check=True)" in new_content
    assert "os.system" not in new_content


def test_patch_applier_sliding_window_match(tmp_path: Path):
    """Verify hunk application matches even if line coordinates shifted slightly."""
    app_file = tmp_path / "service.py"
    # Content has extra leading comment shifting lines by 2
    shifted_content = "# Comment 1\n# Comment 2\ndef process(data):\n    return eval(data)\n"
    app_file.write_text(shifted_content, encoding="utf-8")

    diff = """--- a/service.py
+++ b/service.py
@@ -1,2 +1,2 @@
 def process(data):
-    return eval(data)
+    return ast.literal_eval(data)"""

    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is True
    assert err is None
    assert "ast.literal_eval" in app_file.read_text(encoding="utf-8")


def test_patch_applier_rejects_path_traversal(tmp_path: Path):
    """Verify diff targeting ../../outside is rejected."""
    diff = """--- a/../../etc/passwd
+++ b/../../etc/passwd
@@ -1,1 +1,1 @@
-root
+attacker"""

    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "path traversal" in err.lower()


def test_patch_applier_rejects_absolute_paths(tmp_path: Path):
    """Verify diff targeting /etc/shadow or C:\\ is rejected."""
    diff = """--- a//etc/shadow
+++ b//etc/shadow
@@ -1,1 +1,1 @@
-root:x
+root:pwned"""

    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "absolute path" in err.lower() or "escapes" in err.lower()


def test_patch_applier_missing_target_file(tmp_path: Path):
    """Verify patch targeting non-existent file reports descriptive error."""
    diff = """--- a/missing.py
+++ b/missing.py
@@ -1,1 +1,1 @@
-old
+new"""

    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "does not exist in workspace" in err.lower()


def test_patch_applier_malformed_diff_syntax(tmp_path: Path):
    """Verify empty or invalid diff syntax fails cleanly."""
    applied, err = PatchApplier.apply_patch(tmp_path, "not a diff at all")
    assert applied is False
    assert "no valid file diff headers" in err.lower() or "empty" in err.lower()
