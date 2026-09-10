"""Unit tests for RepositoryService."""

import tempfile
from pathlib import Path
import pytest

from backend.services.repository import RepositoryService, RepositoryValidationError


def test_repository_service_valid_path(tmp_path: Path):
    service = RepositoryService()
    resolved = service.validate_repository_path(str(tmp_path))
    assert resolved == tmp_path.resolve()
    assert resolved.is_dir()


def test_repository_service_empty_path():
    service = RepositoryService()
    with pytest.raises(RepositoryValidationError, match="cannot be empty"):
        service.validate_repository_path("")


def test_repository_service_nonexistent_path():
    service = RepositoryService()
    with pytest.raises(RepositoryValidationError, match="does not exist"):
        service.validate_repository_path("non_existent_directory_12345_xyz")


def test_repository_service_file_not_dir(tmp_path: Path):
    file_path = tmp_path / "test_file.py"
    file_path.write_text("print('hello')")

    service = RepositoryService()
    with pytest.raises(RepositoryValidationError, match="is not a directory"):
        service.validate_repository_path(str(file_path))


def test_repository_service_path_traversal_restricted(tmp_path: Path):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    service = RepositoryService(allowed_base_dir=str(allowed_root))

    # Allowed path should succeed
    assert service.validate_repository_path(str(allowed_root)) == allowed_root.resolve()

    # Outside path should fail
    with pytest.raises(RepositoryValidationError, match="Access denied"):
        service.validate_repository_path(str(outside_dir))


def test_repository_service_get_python_files(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "sub" / "b.py").write_text("y = 2")
    (tmp_path / "c.txt").write_text("text")

    service = RepositoryService()
    py_files = service.get_python_files(str(tmp_path))
    file_names = {f.name for f in py_files}
    assert file_names == {"a.py", "b.py"}
