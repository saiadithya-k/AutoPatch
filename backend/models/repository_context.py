"""Pydantic domain models for Repository Context Service."""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


def get_utc_now() -> datetime:
    """Return timezone-naive UTC datetime for consistent timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CodeLocation(BaseModel):
    """Specific location of code within a file."""
    file_path: str = Field(description="Relative repository path")
    line_start: int = Field(description="1-indexed starting line number")
    line_end: int = Field(description="1-indexed ending line number")
    function_name: Optional[str] = Field(default=None, description="Enclosing function name if any")
    class_name: Optional[str] = Field(default=None, description="Enclosing class name if any")


class ImportStatement(BaseModel):
    """Normalized representation of an imported module or symbol."""
    raw_statement: str = Field(description="Original import line as written in source")
    module: Optional[str] = Field(default=None, description="Imported base module or package name")
    names: list[str] = Field(default_factory=list, description="Specific symbols imported (e.g. ['Any', 'Optional'])")
    alias: Optional[str] = Field(default=None, description="Import alias if specified (e.g. 'as np')")
    is_from_import: bool = Field(default=False, description="Whether statement is a 'from X import Y' construct")


class EnclosingScope(BaseModel):
    """AST-extracted enclosing code structure (function, method, class)."""
    scope_type: str = Field(description="Scope kind: 'function', 'async_function', 'class', 'method', or 'module'")
    name: str = Field(description="Identifier name of the enclosing function or class")
    line_start: int = Field(description="Starting line of the scope definition")
    line_end: int = Field(description="Ending line of the scope definition")
    docstring: Optional[str] = Field(default=None, description="Extracted docstring if present")


class ContextFile(BaseModel):
    """Metadata and bounded content snippet for a related repository file."""
    file_path: str = Field(description="Canonical relative path from repository root")
    file_size_bytes: int = Field(default=0, description="Size of file in bytes")
    total_lines: int = Field(default=0, description="Total line count in file")
    content_snippet: str = Field(default="", description="Bounded snippet or overview content")
    relationship: str = Field(
        default="related_source",
        description="Relationship type: 'vulnerable_file', 'related_source', 'same_directory', or 'imported_module'"
    )


class RelatedTest(BaseModel):
    """Identified test file associated with the vulnerable source component."""
    file_path: str = Field(description="Relative path to test file")
    test_framework: str = Field(default="pytest", description="Inferred test framework ('pytest', 'unittest')")
    test_names: list[str] = Field(default_factory=list, description="List of discovered test function/method names")
    content_snippet: Optional[str] = Field(default=None, description="Bounded content snippet of the test file")


class RepositoryContext(BaseModel):
    """Strongly typed repository context payload providing bounded, safe context for remediation."""
    vulnerability_id: str = Field(description="Associated vulnerability finding ID")
    repository_root: str = Field(description="Canonical path to validated repository root")
    vulnerable_file: str = Field(description="Relative repository path of the affected source file")
    line_start: int = Field(description="Vulnerability starting line number (1-indexed)")
    line_end: int = Field(description="Vulnerability ending line number (1-indexed)")
    language: str = Field(default="python", description="Programming language ('python', 'javascript', 'unknown')")
    code_snippet: Optional[str] = Field(default=None, description="Original raw finding code snippet")
    surrounding_code: str = Field(description="Bounded window of source code around vulnerable line")
    context_window_start: int = Field(description="Starting line number of surrounding_code window")
    context_window_end: int = Field(description="Ending line number of surrounding_code window")
    enclosing_scope: Optional[EnclosingScope] = Field(default=None, description="Enclosing function/class AST scope")
    function_name: Optional[str] = Field(default=None, description="Enclosing function name if resolved")
    class_name: Optional[str] = Field(default=None, description="Enclosing class name if resolved")
    imports: list[ImportStatement] = Field(default_factory=list, description="Extracted import statements from file")
    related_files: list[ContextFile] = Field(default_factory=list, description="Bounded list of relevant related files")
    related_tests: list[RelatedTest] = Field(default_factory=list, description="Discovered associated test files")
    file_size_bytes: int = Field(default=0, description="Total size in bytes of the vulnerable file")
    total_file_lines: int = Field(default=0, description="Total line count of the vulnerable file")
    warnings: list[str] = Field(default_factory=list, description="Non-fatal diagnostics and context warnings")
    created_at: datetime = Field(default_factory=get_utc_now, description="Context extraction timestamp")
