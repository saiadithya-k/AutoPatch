"""AutoPatch Dedicated Patch Application Tool.

Provides cross-platform, deterministic, pure-Python unified diff parsing and application.
Enforces strict security checks (no directory traversal, no URL-encoded traversal, no UNC paths,
no drive letters, no test file modifications, no binary patches, no symlink escapes).
Guarantees atomic patch application: if any hunk in any file fails, the workspace remains
100% untouched.
"""

import logging
import re
import urllib.parse
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class PatchApplicationError(Exception):
    """Raised when patch application fails due to syntax, path violation, or hunk mismatch."""
    pass


class PatchApplier:
    """Dedicated service for applying unified diffs to files within an isolated workspace."""

    @staticmethod
    def _validate_path_safety(file_path: str, workspace_path: Path) -> tuple[bool, Optional[str]]:
        """
        Verify that file path does not attempt path traversal, URL-encoded traversal,
        Windows drive access, UNC access, or repository escape.
        """
        if not file_path or not file_path.strip():
            return False, "Empty file path in diff."

        raw = file_path.strip()

        # 1. URL / Hex Encoded Traversal check (%2e%2e, %2f, %5c)
        decoded = urllib.parse.unquote(raw)
        if decoded != raw:
            # If path contained percent-encoding, check if it was traversal
            norm_decoded = decoded.replace("\\", "/").lower()
            if ".." in norm_decoded.split("/") or norm_decoded.startswith("/"):
                return False, f"Encoded path traversal in '{raw}' is rejected."

        norm = raw.replace("\\", "/")

        # 2. UNC path check (//server/share or \\server\share)
        if raw.startswith("\\\\") or raw.startswith("//"):
            return False, f"UNC path '{raw}' is rejected."

        # 3. Windows drive-letter path check (C:, D:, etc.)
        if len(norm) > 1 and norm[1] == ":":
            return False, f"Drive-letter path '{raw}' is rejected."

        # 4. Absolute path check
        if norm.startswith("/"):
            return False, f"Absolute path '{raw}' is rejected."

        # 5. Directory traversal check
        parts = norm.split("/")
        if ".." in parts or "." in parts[:-1]:
            if ".." in parts:
                return False, f"Path traversal '{raw}' is rejected."

        # 6. /dev/null check
        if norm == "/dev/null":
            return False, "File path /dev/null is rejected (unexpected creation/deletion)."

        # 7. Test file protection: patches must not touch tests
        lower_parts = [p.lower() for p in parts]
        if "tests" in lower_parts or "test" in lower_parts or any(p.startswith("test_") or p.endswith("_test.py") for p in lower_parts):
            return False, f"Modifying test files ('{raw}') is strictly prohibited."

        # 8. Boundary resolution check
        target = (workspace_path / norm).resolve()
        try:
            target.relative_to(workspace_path.resolve())
        except ValueError:
            return False, f"Path '{raw}' escapes workspace boundary."

        # 9. Symlink escape check
        if target.is_symlink():
            try:
                real_target = target.resolve(strict=False)
                real_target.relative_to(workspace_path.resolve())
            except (ValueError, RuntimeError):
                return False, f"Path '{raw}' is a symlink escaping workspace boundary."

        return True, None

    @classmethod
    def parse_unified_diff(cls, diff_text: str, strict_counts: bool = False) -> list[dict]:
        """
        Parse unified diff into structured file entries with individual hunks.
        Validates both --- and +++ paths, hunk counts, and rejects binary patches.
        """
        if not diff_text or not diff_text.strip():
            raise PatchApplicationError("Unified diff is empty.")

        # Reject binary diffs
        if "GIT binary patch" in diff_text or "\0" in diff_text:
            raise PatchApplicationError("Binary diffs are not supported.")

        files = []
        current_file = None
        current_hunk = None

        lines = diff_text.splitlines(keepends=True)
        i = 0
        while i < len(lines):
            line = lines[i]

            if line.startswith("--- "):
                from_raw = line[4:].strip().split("\t")[0]
                if from_raw.startswith("a/"):
                    from_raw = from_raw[2:]

                # Expect +++ line immediately following ---
                if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
                    raise PatchApplicationError(f"Missing '+++' header following '---' at line {i + 1}.")

                to_raw = lines[i + 1][4:].strip().split("\t")[0]
                if to_raw.startswith("b/"):
                    to_raw = to_raw[2:]

                norm_from = from_raw.replace("\\", "/").strip()
                norm_to = to_raw.replace("\\", "/").strip()

                # Validate that from and to paths refer to the same file
                if norm_from != norm_to:
                    raise PatchApplicationError(
                        f"Source path '{norm_from}' and destination path '{norm_to}' do not match. File renaming or new creation/deletion is not allowed."
                    )

                if norm_to == "/dev/null" or norm_from == "/dev/null":
                    raise PatchApplicationError("File creation or deletion via /dev/null is not permitted.")

                current_file = {
                    "from_file": norm_from,
                    "to_file": norm_to,
                    "hunks": [],
                }
                files.append(current_file)
                current_hunk = None
                i += 2
                continue

            if line.startswith("@@ ") and current_file is not None:
                # Parse hunk header: @@ -orig_start,orig_count +new_start,new_count @@
                m = re.match(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@", line)
                if not m:
                    raise PatchApplicationError(f"Malformed hunk header: '{line.strip()}'.")

                orig_start = int(m.group(1))
                orig_count = int(m.group(2)) if m.group(2) is not None else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) is not None else 1

                current_hunk = {
                    "orig_start": orig_start,
                    "orig_count": orig_count,
                    "new_start": new_start,
                    "new_count": new_count,
                    "lines": [],
                }
                current_file["hunks"].append(current_hunk)
                i += 1
                continue

            if current_hunk is not None:
                if line.startswith(("+", "-", " ")) or line.startswith("\\ No newline"):
                    current_hunk["lines"].append(line)
                elif line.strip() == "":
                    # Blank line treated as context line
                    current_hunk["lines"].append(" \n")
                elif line.startswith("--- ") or line.startswith("@@ "):
                    # Next section starts
                    continue

            i += 1

        if not files:
            raise PatchApplicationError("No valid file diff headers found in unified diff.")

        # Validate hunk counts match actual line contents
        for f_entry in files:
            for hunk in f_entry["hunks"]:
                actual_orig_count = 0
                actual_new_count = 0
                for hline in hunk["lines"]:
                    if hline.startswith("\\ No newline"):
                        continue
                    if hline.startswith("-"):
                        actual_orig_count += 1
                    elif hline.startswith("+"):
                        actual_new_count += 1
                    elif hline.startswith(" "):
                        actual_orig_count += 1
                        actual_new_count += 1

                mismatch = False
                if strict_counts:
                    mismatch = (actual_orig_count != hunk["orig_count"] or actual_new_count != hunk["new_count"])
                else:
                    # Orig count must match; new_count allows at most 1 line delta for trailing newline variance
                    mismatch = (actual_orig_count != hunk["orig_count"] or abs(actual_new_count - hunk["new_count"]) > 1)

                if mismatch:
                    raise PatchApplicationError(
                        f"Hunk at line {hunk['orig_start']} header counts (-{hunk['orig_count']}, +{hunk['new_count']}) "
                        f"do not match actual lines in hunk (-{actual_orig_count}, +{actual_new_count})."
                    )

        return files

    @classmethod
    def apply_patch(
        cls,
        workspace_path: Path,
        unified_diff: str,
        strict_counts: bool = False,
    ) -> tuple[bool, Optional[str]]:
        """
        Apply unified diff directly to files inside workspace_path.
        Operates ATOMICALLY: if any hunk in any file cannot be applied cleanly,
        the workspace is left completely unchanged.

        :param workspace_path: Root of the isolated temporary workspace.
        :param unified_diff: Unified diff string.
        :param strict_counts: If True, hunk counts must match character-for-character with zero line delta.
        :return: (True, None) if applied cleanly, or (False, error_message).
        """
        workspace_path = Path(workspace_path).resolve()
        if not workspace_path.exists() or not workspace_path.is_dir():
            return False, f"Workspace path '{workspace_path}' does not exist."

        try:
            parsed_files = cls.parse_unified_diff(unified_diff, strict_counts=strict_counts)
        except PatchApplicationError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Failed to parse unified diff: {str(e)}"

        # Validate all target files exist before modifying anything
        for file_entry in parsed_files:
            rel_path = file_entry["to_file"]

            is_safe, err = cls._validate_path_safety(rel_path, workspace_path)
            if not is_safe:
                return False, err

            target_file = workspace_path / rel_path
            if not target_file.exists() or not target_file.is_file():
                return False, f"Target file '{rel_path}' does not exist in workspace or is not a regular file."

        # Stage all file modifications in memory first (guarantees file-level & workspace-level atomicity)
        staged_files: dict[Path, str] = {}

        for file_entry in parsed_files:
            rel_path = file_entry["to_file"]
            target_file = workspace_path / rel_path

            try:
                original_text = target_file.read_text(encoding="utf-8")
            except Exception as e:
                return False, f"Could not read target file '{rel_path}': {e}"

            orig_lines = original_text.splitlines(keepends=True)
            if not orig_lines and original_text:
                orig_lines = [original_text]

            modified_lines = list(orig_lines)
            line_offset = 0

            for hunk in file_entry["hunks"]:
                orig_start = hunk["orig_start"]

                expected_orig: list[str] = []
                replacement_lines: list[str] = []

                previous_prefix = None
                for hline in hunk["lines"]:
                    if hline.startswith("\\ No newline"):
                        if previous_prefix in (" ", "-") and expected_orig:
                            expected_orig[-1] = expected_orig[-1].rstrip("\r\n")
                        if previous_prefix in (" ", "+") and replacement_lines:
                            replacement_lines[-1] = replacement_lines[-1].rstrip("\r\n")
                        continue
                    # Ensure trailing newline is preserved
                    norm_line = hline if hline.endswith("\n") else hline + "\n"
                    if norm_line.startswith(" "):
                        expected_orig.append(norm_line[1:])
                        replacement_lines.append(norm_line[1:])
                    elif norm_line.startswith("-"):
                        expected_orig.append(norm_line[1:])
                    elif norm_line.startswith("+"):
                        replacement_lines.append(norm_line[1:])
                    previous_prefix = norm_line[0]

                target_start = orig_start - 1 + line_offset
                hunk_matched = False
                actual_start = -1

                # 1. EXACT match at target position (including exact indentation and whitespace)
                if 0 <= target_start <= len(modified_lines):
                    target_slice = modified_lines[target_start : target_start + len(expected_orig)]
                    if target_slice == expected_orig:
                        hunk_matched = True
                        actual_start = target_start

                # 2. Strictly bounded sliding window (±10 lines) if line numbers shifted
                # STILL REQUIRES EXACT CONTENT MATCHING (no strip() relaxation that ignores indentation)
                if not hunk_matched and expected_orig:
                    search_min = max(0, target_start - 10)
                    search_max = min(len(modified_lines) - len(expected_orig) + 1, target_start + 10)

                    for s_idx in range(search_min, max(search_min + 1, search_max)):
                        slice_lines = modified_lines[s_idx : s_idx + len(expected_orig)]
                        if slice_lines == expected_orig:
                            hunk_matched = True
                            actual_start = s_idx
                            break

                # 3. Pure insertion check (if expected_orig is empty)
                if not hunk_matched and not expected_orig:
                    actual_start = max(0, min(len(modified_lines), target_start))
                    hunk_matched = True

                if not hunk_matched:
                    return False, f"Hunk at line {orig_start} could not be matched exactly in '{rel_path}'."

                # Apply hunk replacement in memory
                modified_lines[actual_start : actual_start + len(expected_orig)] = replacement_lines
                line_offset += len(replacement_lines) - len(expected_orig)

            staged_files[target_file] = "".join(modified_lines)

        # ATOMIC WRITE: Write all staged files to disk only after every hunk and file succeeded
        written_backups: dict[Path, str] = {}
        try:
            for target_file, new_content in staged_files.items():
                written_backups[target_file] = target_file.read_text(encoding="utf-8")
                target_file.write_text(new_content, encoding="utf-8")
                logger.info("Successfully applied patch to '%s' in workspace.", target_file.name)
        except Exception as e:
            # Rollback any written files to ensure atomicity
            for rolled_file, old_content in written_backups.items():
                try:
                    rolled_file.write_text(old_content, encoding="utf-8")
                except Exception:
                    pass
            return False, f"Atomic patch application failed during file write: {e}"

        return True, None
