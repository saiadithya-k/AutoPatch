"""Unit tests for TemporaryWorkspace manager and security boundary enforcement."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.tools.workspace import TemporaryWorkspace


def test_workspace_creation_and_cleanup(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "file1.txt").write_text("content 1", encoding="utf-8")

    with TemporaryWorkspace(repo) as ws:
        assert ws.exists()
        assert (ws / "file1.txt").exists()
        assert (ws / "file1.txt").read_text(encoding="utf-8") == "content 1"
        assert ws.resolve() != repo.resolve()
        temp_dir = str(ws)

    # After exit, workspace is automatically cleaned up
    assert not os.path.exists(temp_dir)


def test_workspace_excludes_ignored_directories(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("git config", encoding="utf-8")
    (repo / "main.py").write_text("print('hello')", encoding="utf-8")

    with TemporaryWorkspace(repo) as ws:
        assert (ws / "main.py").exists()
        assert not (ws / ".git").exists()


def test_workspace_rejects_nonexistent_repo():
    with pytest.raises(ValueError, match="does not exist"):
        with TemporaryWorkspace(Path("/nonexistent/path/for/autopatch")):
            pass


def test_workspace_skips_external_symlinks(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside_secret = tmp_path / "secret.txt"
    outside_secret.write_text("super_secret", encoding="utf-8")

    symlink_file = repo / "sym_secret.txt"
    try:
        symlink_file.symlink_to(outside_secret)
    except (OSError, NotImplementedError):
        # Fallback test with mocking
        pass

    with TemporaryWorkspace(repo) as ws:
        # File pointing outside repository boundary should not be copied
        assert not (ws / "sym_secret.txt").exists()


def test_workspace_handles_broken_symlinks(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    broken_link = repo / "broken.txt"
    try:
        broken_link.symlink_to(repo / "does_not_exist.txt")
    except (OSError, NotImplementedError):
        pass

    # Should not crash on broken symlinks
    with TemporaryWorkspace(repo) as ws:
        assert ws.exists()
