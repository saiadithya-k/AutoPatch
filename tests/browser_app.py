"""Browser-test entry point: real API + reference model + isolated persisted evidence.

Never imported by production. Playwright provides a new database and repository
directory for every launch; no test endpoints are added to the application.
"""
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ["AUTOPATCH_E2E_ROOT"]).resolve()
if not ROOT.is_relative_to((PROJECT / ".test-artifacts").resolve()):
    raise RuntimeError("Browser fixtures must stay inside .test-artifacts")
expected = f"sqlite:///{(ROOT / 'browser-e2e.db').as_posix()}"
if os.environ.get("DATABASE_URL") != expected:
    raise RuntimeError("Browser tests require their isolated browser-e2e.db")

from backend.main import app
from backend.database.database import SessionLocal
from backend.database.models import ValidationResultModel, PatchAttemptModel
from scripts.demo_workflow import create_demo_repository, run_demo

original_lifespan = app.router.lifespan_context


@asynccontextmanager
async def browser_lifespan(application):
    async with original_lifespan(application):
        for name in ("approve-case", "reject-case", "incomplete-case"):
            repository = ROOT / name
            create_demo_repository(repository)
            with SessionLocal() as db:
                workflow = run_demo(db, repository)
                if workflow.status != "READY_FOR_REVIEW":
                    raise RuntimeError(f"Browser fixture failed: {workflow.error_message}")
                if name == "incomplete-case":
                    # Deliberately inconsistent legacy evidence must fail closed in UI and API.
                    ids = [p.id for p in db.query(PatchAttemptModel).filter_by(workflow_id=workflow.id).all()]
                    for record in db.query(ValidationResultModel).filter(ValidationResultModel.patch_attempt_id.in_(ids)):
                        record.scanner_metadata = json.dumps({"coverage_complete": False})
                    db.commit()
        (ROOT / "clean-case").mkdir()
        (ROOT / "clean-case" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        yield


app.router.lifespan_context = browser_lifespan
