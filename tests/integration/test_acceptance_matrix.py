"""Reference and opt-in real-model checks share the same controlled repositories."""
import json
from pathlib import Path

import pytest
from fastapi.encoders import jsonable_encoder

from scripts.acceptance_cases import CASES
from scripts.run_acceptance import check_prerequisites, execute_case


@pytest.mark.scanners
@pytest.mark.parametrize("name", CASES)
def test_reference_acceptance(name, tmp_path, db_session):
    result = execute_case(CASES[name], tmp_path / name, db_session)
    assert result["passed"], result["report"]["workflow"]["errors"]
    if name == "multifile_sql":
        assert all(set(p["files_changed"]) == {"app.py", "query_builder.py"}
                   for p in result["report"]["patches"])


@pytest.fixture(scope="session")
def live_ollama():
    # Explicit opt-in must fail if unavailable, rather than silently skip a requested gate.
    check_prerequisites(live_model=True)


@pytest.mark.live_model
@pytest.mark.scanners
@pytest.mark.parametrize("name", CASES)
def test_live_ollama_acceptance(name, tmp_path, db_session, live_ollama):
    result = execute_case(CASES[name], tmp_path / name, db_session, live_model=True)
    artifact = Path(__file__).resolve().parents[2] / ".test-artifacts" / "live-acceptance"
    artifact.mkdir(parents=True, exist_ok=True)
    (artifact / f"{name}.json").write_text(json.dumps(jsonable_encoder(result), indent=2), encoding="utf-8")
    assert result["passed"], result["report"]["workflow"]["errors"]
