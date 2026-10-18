"""Pytest fixtures and test configuration."""

import os
import tempfile
from pathlib import Path
from typing import Generator
import pytest

# Client lifespan initializes the production engine. Keep tests off the local database.
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.database.database import Base, get_db
from backend.main import app

from sqlalchemy.pool import StaticPool

# Test SQLite In-Memory Database
TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Provide a fresh isolated in-memory database session for each test."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a FastAPI test client using the test database session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def vulnerable_repo_path() -> Path:
    """Path to the demo vulnerable project."""
    return Path(__file__).parent / "vulnerable_project"


@pytest.fixture
def temp_clean_repo() -> Generator[Path, None, None]:
    """Provide a temporary clean Python repository for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        clean_file = tmp_path / "calculator.py"
        clean_file.write_text(
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
        )
        yield tmp_path


def pytest_addoption(parser):
    parser.addoption("--run-docker", action="store_true", help="Require real Docker acceptance checks")
    parser.addoption("--run-live-model", action="store_true", help="Send real requests to the configured local Ollama model")
    parser.addoption("--validator-image", default="autopatch-validator-acceptance:latest", help="Prebuilt trusted validator image for Docker acceptance")


def pytest_collection_modifyitems(config, items):
    """Identify existing real-tool tests without silently skipping missing prerequisites."""
    scanner_files = {
        "test_scan_integration.py", "test_api_scan.py", "test_api_patch.py",
        "test_risk_assessment_integration.py", "test_repository_context_integration.py",
        "test_patch_generation_integration.py", "test_validation_integration.py",
    }
    scanner_functions = {
        "test_bandit_runner_successful_execution", "test_semgrep_runner_successful_execution",
        "test_semgrep_runner_custom_config",
    }
    for item in items:
        if Path(str(item.path)).name in scanner_files or item.originalname in scanner_functions:
            item.add_marker(pytest.mark.scanners)
        if item.get_closest_marker("docker") and not config.getoption("--run-docker"):
            item.add_marker(pytest.mark.skip(reason="Explicit opt-in required: --run-docker"))
        if item.get_closest_marker("live_model") and not config.getoption("--run-live-model"):
            item.add_marker(pytest.mark.skip(reason="Explicit opt-in required: --run-live-model"))
