"""AutoPatch Repository Context Service.

Extracts bounded, safe, structured repository context (surrounding lines,
Python AST enclosing functions/classes, imports, related files, related tests)
around a vulnerability finding without executing any repository code.
"""

import ast
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from backend.config import get_settings
from backend.models.repository_context import (
    CodeLocation,
    ContextFile,
    EnclosingScope,
    ImportStatement,
    RelatedTest,
    RepositoryContext,
)
from backend.models.vulnerability import VulnerabilityFinding
from backend.services.repository import RepositoryService, RepositoryValidationError

logger = logging.getLogger(__name__)


class RepositoryContextService:
    """Service for safe, bounded contextual extraction from target repositories."""

    # Obvious secret patterns for passive context redaction (leaves repository on disk untouched)
    SECRET_PATTERNS = [
        re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*=\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]

    LANGUAGE_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".c": "c",
        ".cpp": "cpp",
        ".rs": "rust",
        ".php": "php",
    }

    def __init__(
        self,
        repository_service: Optional[RepositoryService] = None,
        context_lines_before: Optional[int] = None,
        context_lines_after: Optional[int] = None,
        max_file_size_bytes: Optional[int] = None,
        max_context_files: Optional[int] = None,
        max_context_lines: Optional[int] = None,
        enable_secret_redaction: bool = True,
    ):
        """
        Initialize Repository Context Service with bounded limits and security configurations.
        """
        settings = get_settings()
        self.repository_service = repository_service or RepositoryService()
        self.context_lines_before = context_lines_before or settings.CONTEXT_LINES_BEFORE
        self.context_lines_after = context_lines_after or settings.CONTEXT_LINES_AFTER
        self.max_file_size_bytes = max_file_size_bytes or settings.MAX_CONTEXT_FILE_SIZE
        self.max_context_files = max_context_files or settings.MAX_CONTEXT_FILES
        self.max_context_lines = max_context_lines or settings.MAX_CONTEXT_LINES
        self.enable_secret_redaction = enable_secret_redaction

    def _resolve_and_validate_file_path(
        self,
        repo_root: Path,
        raw_file_path: str
    ) -> tuple[Optional[Path], Optional[str]]:
        """
        Safely resolve target file path and guarantee it remains strictly within repo_root.
        Prevents path traversal, absolute drive escape, UNC paths, and symlink breakout.

        :param repo_root: Validated canonical repository root.
        :param raw_file_path: Relative or candidate file path from finding.
        :return: Tuple of (Resolved Path or None, Error/Warning message or None).
        """
        if not raw_file_path or not raw_file_path.strip():
            return None, "File path is empty."

        clean_path_str = raw_file_path.replace("\\", "/").strip()

        # Reject obvious path traversal patterns upfront
        if ".." in clean_path_str.split("/"):
            return None, f"Path traversal attempt detected in '{raw_file_path}'."

        try:
            target_path = (repo_root / clean_path_str).resolve()
        except Exception as e:
            return None, f"Invalid path syntax '{raw_file_path}': {e}"

        # Containment verification: target_path must be relative to repo_root
        try:
            target_path.relative_to(repo_root)
        except ValueError:
            return None, f"Access denied: Path '{raw_file_path}' resolves outside repository root."

        # Symlink breakout check: if file is a symlink, verify real target is inside repo_root
        if target_path.is_symlink():
            try:
                real_target = target_path.resolve(strict=True)
                real_target.relative_to(repo_root)
            except (ValueError, FileNotFoundError) as e:
                return None, f"Symlink traversal escape detected for '{raw_file_path}': {e}"

        return target_path, None

    def _detect_language(self, file_path: Path) -> str:
        """Detect source code programming language by file extension."""
        ext = file_path.suffix.lower()
        return self.LANGUAGE_EXTENSIONS.get(ext, "unknown")

    def _read_file_safely(self, file_path: Path) -> tuple[Optional[str], list[str], list[str]]:
        """
        Read file contents safely with size limits, binary detection, and encoding fallbacks.

        :param file_path: Canonical resolved file path.
        :return: Tuple of (full_content, list_of_lines, list_of_warnings).
        """
        warnings: list[str] = []

        if not file_path.exists():
            warnings.append(f"file_not_found: File '{file_path.name}' does not exist on disk.")
            return None, [], warnings

        if not file_path.is_file():
            warnings.append(f"not_a_file: Path '{file_path.name}' is not a regular file.")
            return None, [], warnings

        # File size check
        try:
            size = file_path.stat().st_size
            if size > self.max_file_size_bytes:
                warnings.append(
                    f"file_too_large: File size ({size} bytes) exceeds limit ({self.max_file_size_bytes} bytes)."
                )
                return None, [], warnings
        except Exception as e:
            warnings.append(f"stat_error: Could not check file size: {e}")
            return None, [], warnings

        # Binary check (inspect first 1024 bytes)
        try:
            with open(file_path, "rb") as f:
                header = f.read(1024)
                if b"\x00" in header:
                    warnings.append(f"binary_file: File '{file_path.name}' appears to be binary.")
                    return None, [], warnings
        except Exception as e:
            warnings.append(f"read_error: Could not inspect file header: {e}")
            return None, [], warnings

        # Safe multi-encoding decode
        content: Optional[str] = None
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                with open(file_path, "r", encoding=enc) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                warnings.append(f"read_error: Failed reading file: {e}")
                return None, [], warnings

        if content is None:
            warnings.append(f"decode_error: Unable to decode file '{file_path.name}' with standard encodings.")
            return None, [], warnings

        lines = content.splitlines(keepends=False)
        return content, lines, warnings

    def _extract_surrounding_code(
        self,
        lines: list[str],
        line_start: int,
        line_end: int,
    ) -> tuple[str, int, int]:
        """
        Extract bounded window of code lines around the target line range.

        :param lines: Complete list of lines from the file.
        :param line_start: 1-indexed starting line of vulnerability.
        :param line_end: 1-indexed ending line of vulnerability.
        :return: Tuple of (surrounding_code_string, window_start_line, window_end_line).
        """
        total_lines = len(lines)
        if total_lines == 0:
            return "", 1, 1

        # Bound inputs
        safe_start = max(1, min(line_start, total_lines))
        safe_end = max(safe_start, min(line_end, total_lines))

        # Calculate window
        window_start = max(1, safe_start - self.context_lines_before)
        window_end = min(total_lines, safe_end + self.context_lines_after)

        # Enforce max lines budget
        if (window_end - window_start + 1) > self.max_context_lines:
            window_end = window_start + self.max_context_lines - 1

        selected_lines = lines[window_start - 1 : window_end]
        surrounding_code = "\n".join(selected_lines)

        return surrounding_code, window_start, window_end

    def _extract_python_ast(
        self,
        source_code: str,
        target_line: int,
    ) -> tuple[Optional[EnclosingScope], Optional[str], Optional[str], list[ImportStatement], list[str]]:
        """
        Statically analyze Python source code via AST to extract enclosing scopes and imports.
        Never executes any code or imports.

        :param source_code: Complete Python source code string.
        :param target_line: 1-indexed line of the vulnerability finding.
        :return: Tuple of (EnclosingScope, function_name, class_name, list of ImportStatement, list of warnings).
        """
        warnings: list[str] = []
        imports: list[ImportStatement] = []

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            warnings.append(f"ast_parse_error: SyntaxError at line {e.lineno}: {e.msg}")
            return None, None, None, [], warnings
        except Exception as e:
            warnings.append(f"ast_parse_error: {str(e)}")
            return None, None, None, [], warnings

        # 1. Extract imports statically
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    raw = f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                    imports.append(
                        ImportStatement(
                            raw_statement=raw,
                            module=alias.name,
                            names=[alias.name],
                            alias=alias.asname,
                            is_from_import=False,
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                names = [alias.name for alias in node.names]
                raw = f"from {mod} import {', '.join(names)}"
                imports.append(
                    ImportStatement(
                        raw_statement=raw,
                        module=mod,
                        names=names,
                        is_from_import=True,
                    )
                )

        # 2. Extract enclosing scope (innermost function/method and class)
        matched_scopes: list[tuple[ast.AST, str, str, int, int]] = []

        def _traverse(node: ast.AST, current_class: Optional[str] = None):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    start = getattr(child, "lineno", 1)
                    end = getattr(child, "end_lineno", start)
                    if start <= target_line <= end:
                        matched_scopes.append((child, "class", child.name, start, end))
                    _traverse(child, current_class=child.name)
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = getattr(child, "lineno", 1)
                    end = getattr(child, "end_lineno", start)
                    scope_type = "method" if current_class else ("async_function" if isinstance(child, ast.AsyncFunctionDef) else "function")
                    if start <= target_line <= end:
                        matched_scopes.append((child, scope_type, child.name, start, end))
                    _traverse(child, current_class=current_class)
                else:
                    _traverse(child, current_class=current_class)

        _traverse(tree)

        enclosing_scope: Optional[EnclosingScope] = None
        function_name: Optional[str] = None
        class_name: Optional[str] = None

        if matched_scopes:
            # Sort by span (end - start) ascending so innermost scope comes first
            matched_scopes.sort(key=lambda s: (s[4] - s[3]))
            innermost_node, scope_type, name, s_line, e_line = matched_scopes[0]

            docstring = ast.get_docstring(innermost_node)
            enclosing_scope = EnclosingScope(
                scope_type=scope_type,
                name=name,
                line_start=s_line,
                line_end=e_line,
                docstring=docstring,
            )

            if scope_type in ("function", "async_function", "method"):
                function_name = name
                # Look for enclosing class if any
                for _, s_type, c_name, _, _ in matched_scopes[1:]:
                    if s_type == "class":
                        class_name = c_name
                        break
            elif scope_type == "class":
                class_name = name

        return enclosing_scope, function_name, class_name, imports, warnings

    def _discover_related_files(
        self,
        repo_root: Path,
        target_file: Path,
        imports: list[ImportStatement],
    ) -> list[ContextFile]:
        """
        Discover relevant adjacent source files using conservative, bounded heuristics.
        """
        related_files: list[ContextFile] = []
        visited: set[Path] = {target_file.resolve()}

        # Heuristic 1: Local imported modules in the same repository
        for imp in imports:
            if len(related_files) >= self.max_context_files:
                break
            if imp.module:
                # E.g. 'from database import ...' -> check 'database.py' in target directory or repo root
                candidates = [
                    target_file.parent / f"{imp.module}.py",
                    repo_root / f"{imp.module}.py",
                    repo_root / f"{imp.module.replace('.', '/')}.py",
                ]
                for cand in candidates:
                    resolved_cand = cand.resolve()
                    if resolved_cand.exists() and resolved_cand.is_file() and resolved_cand not in visited:
                        try:
                            resolved_cand.relative_to(repo_root)
                            visited.add(resolved_cand)
                            content, lines, _ = self._read_file_safely(resolved_cand)
                            snippet = "\n".join(lines[:25]) if lines else ""
                            rel_path = resolved_cand.relative_to(repo_root).as_posix()
                            related_files.append(
                                ContextFile(
                                    file_path=rel_path,
                                    file_size_bytes=resolved_cand.stat().st_size,
                                    total_lines=len(lines),
                                    content_snippet=snippet,
                                    relationship="imported_module",
                                )
                            )
                            break
                        except ValueError:
                            pass

        # Heuristic 2: Sibling source files in the same directory (up to budget)
        if target_file.parent.exists() and len(related_files) < self.max_context_files:
            try:
                for sibling in sorted(target_file.parent.iterdir()):
                    if len(related_files) >= self.max_context_files:
                        break
                    if sibling.is_file() and sibling.suffix == target_file.suffix and sibling.resolve() not in visited:
                        # Exclude obvious test files from related_files (they are handled in related_tests)
                        if sibling.name.startswith("test_") or sibling.name.endswith("_test.py"):
                            continue
                        visited.add(sibling.resolve())
                        content, lines, _ = self._read_file_safely(sibling)
                        snippet = "\n".join(lines[:25]) if lines else ""
                        rel_path = sibling.relative_to(repo_root).as_posix()
                        related_files.append(
                            ContextFile(
                                file_path=rel_path,
                                file_size_bytes=sibling.stat().st_size,
                                total_lines=len(lines),
                                content_snippet=snippet,
                                relationship="same_directory",
                            )
                        )
            except Exception as e:
                logger.debug("Error iterating siblings in %s: %s", target_file.parent, e)

        return related_files

    def _discover_related_tests(
        self,
        repo_root: Path,
        target_file: Path,
    ) -> list[RelatedTest]:
        """
        Discover associated test files for a vulnerable source file.
        Matches test naming conventions (test_<name>.py, <name>_test.py, tests/test_<name>.py).
        """
        related_tests: list[RelatedTest] = []
        base_name = target_file.stem  # e.g., 'app' from 'app.py'

        # Candidate test file paths
        candidate_rel_paths = [
            f"test_{base_name}.py",
            f"{base_name}_test.py",
            f"tests/test_{base_name}.py",
            f"tests/{base_name}_test.py",
            f"test/test_{base_name}.py",
            f"tests/test_{target_file.name}",
        ]

        # Also check relative directory match (e.g., auth/service.py -> tests/auth/test_service.py)
        try:
            rel_to_root = target_file.relative_to(repo_root)
            if len(rel_to_root.parts) > 1:
                parent_subpath = "/".join(rel_to_root.parts[:-1])
                candidate_rel_paths.append(f"{parent_subpath}/test_{base_name}.py")
                candidate_rel_paths.append(f"tests/{parent_subpath}/test_{base_name}.py")
        except ValueError:
            pass

        seen: set[Path] = set()

        for cand_str in candidate_rel_paths:
            cand_path = (repo_root / cand_str).resolve()
            if cand_path.exists() and cand_path.is_file() and cand_path not in seen:
                try:
                    cand_path.relative_to(repo_root)
                    seen.add(cand_path)
                    content, lines, _ = self._read_file_safely(cand_path)

                    test_names: list[str] = []
                    # Statically extract test function names if Python
                    if cand_path.suffix == ".py" and content:
                        try:
                            tree = ast.parse(content)
                            for node in ast.walk(tree):
                                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                    if node.name.startswith("test_"):
                                        test_names.append(node.name)
                        except Exception:
                            pass

                    rel_path = cand_path.relative_to(repo_root).as_posix()
                    snippet = "\n".join(lines[:30]) if lines else ""

                    related_tests.append(
                        RelatedTest(
                            file_path=rel_path,
                            test_framework="pytest" if "pytest" in (content or "") or test_names else "unittest",
                            test_names=test_names,
                            content_snippet=snippet,
                        )
                    )
                except ValueError:
                    pass

        return related_tests

    def _redact_secrets(self, code_text: str) -> str:
        """
        Redact obvious high-entropy API keys and secrets from context sent to LLMs.
        Does NOT alter the original source file on the filesystem.
        """
        if not self.enable_secret_redaction or not code_text:
            return code_text

        redacted = code_text
        for pattern in self.SECRET_PATTERNS:
            redacted = pattern.sub("[REDACTED_SECRET]", redacted)
        return redacted

    def build_context(
        self,
        repository_root: str | Path,
        finding: VulnerabilityFinding,
    ) -> RepositoryContext:
        """
        Extract bounded, structured repository context for a vulnerability finding.

        :param repository_root: Local filesystem path to repository root.
        :param finding: Normalized VulnerabilityFinding instance.
        :return: Strongly typed RepositoryContext model.
        """
        warnings: list[str] = []

        # 1. Validate repository root path
        try:
            validated_root = self.repository_service.validate_repository_path(str(repository_root))
        except RepositoryValidationError as e:
            logger.warning("Repository root validation failed: %s", e)
            return RepositoryContext(
                vulnerability_id=finding.id,
                repository_root=str(repository_root),
                vulnerable_file=finding.file_path,
                line_start=finding.line_start or 1,
                line_end=finding.line_end or 1,
                language="unknown",
                code_snippet=finding.code_snippet,
                surrounding_code="",
                context_window_start=1,
                context_window_end=1,
                warnings=[f"invalid_repository_root: {str(e)}"],
            )

        # 2. Resolve and validate target file path with containment guards
        target_path, path_err = self._resolve_and_validate_file_path(validated_root, finding.file_path)
        if path_err or target_path is None:
            warnings.append(path_err or "Invalid file path.")
            return RepositoryContext(
                vulnerability_id=finding.id,
                repository_root=str(validated_root),
                vulnerable_file=finding.file_path,
                line_start=finding.line_start or 1,
                line_end=finding.line_end or 1,
                language="unknown",
                code_snippet=finding.code_snippet,
                surrounding_code="",
                context_window_start=1,
                context_window_end=1,
                warnings=warnings,
            )

        # 3. Detect language
        language = self._detect_language(target_path)
        rel_vulnerable_path = target_path.relative_to(validated_root).as_posix()

        # 4. Safely read file content
        content, lines, read_warnings = self._read_file_safely(target_path)
        warnings.extend(read_warnings)

        if content is None or not lines:
            return RepositoryContext(
                vulnerability_id=finding.id,
                repository_root=str(validated_root),
                vulnerable_file=rel_vulnerable_path,
                line_start=finding.line_start or 1,
                line_end=finding.line_end or 1,
                language=language,
                code_snippet=finding.code_snippet,
                surrounding_code="",
                context_window_start=1,
                context_window_end=1,
                file_size_bytes=target_path.stat().st_size if target_path.exists() else 0,
                total_file_lines=0,
                warnings=warnings,
            )

        total_lines = len(lines)
        file_size = target_path.stat().st_size
        line_start = finding.line_start or 1
        line_end = finding.line_end or line_start

        # 5. Extract bounded surrounding lines
        surrounding_code, window_start, window_end = self._extract_surrounding_code(
            lines=lines,
            line_start=line_start,
            line_end=line_end,
        )

        # 6. AST-based function/class/import extraction for Python
        enclosing_scope: Optional[EnclosingScope] = None
        function_name: Optional[str] = None
        class_name: Optional[str] = None
        imports: list[ImportStatement] = []

        if language == "python":
            enclosing_scope, function_name, class_name, imports, ast_warnings = self._extract_python_ast(
                source_code=content,
                target_line=line_start,
            )
            warnings.extend(ast_warnings)
        elif language == "unknown":
            warnings.append("unsupported_language: AST extraction not available for this file type.")

        # 7. Discover related files and tests
        related_files = self._discover_related_files(validated_root, target_path, imports)
        related_tests = self._discover_related_tests(validated_root, target_path)

        # 8. Apply secret redaction to context string
        if self.enable_secret_redaction:
            surrounding_code = self._redact_secrets(surrounding_code)

        return RepositoryContext(
            vulnerability_id=finding.id,
            repository_root=str(validated_root),
            vulnerable_file=rel_vulnerable_path,
            line_start=line_start,
            line_end=line_end,
            language=language,
            code_snippet=finding.code_snippet,
            surrounding_code=surrounding_code,
            context_window_start=window_start,
            context_window_end=window_end,
            enclosing_scope=enclosing_scope,
            function_name=function_name,
            class_name=class_name,
            imports=imports,
            related_files=related_files,
            related_tests=related_tests,
            file_size_bytes=file_size,
            total_file_lines=total_lines,
            warnings=warnings,
        )
