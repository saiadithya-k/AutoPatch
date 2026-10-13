"""Reproducible scripted-model demo using real compilation, pytest and scanners."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEMO_SOURCE = "def parse_literal(expression):\n    return eval(expression)\n"
DEMO_TEST = '''import unittest
from app import parse_literal

class TestLiteralParser(unittest.TestCase):
    def test_dictionary(self):
        self.assertEqual(parse_literal("{'count': 3}"), {"count": 3})

    def test_list(self):
        self.assertEqual(parse_literal("[1, 2, 3]"), [1, 2, 3])
'''


def create_demo_repository(repository: Path) -> None:
    repository.mkdir(parents=True, exist_ok=True)
    for name, content in {"app.py": DEMO_SOURCE, "test_app.py": DEMO_TEST}.items():
        path = repository / name
        if path.exists() and path.read_text(encoding="utf-8") != content:
            raise ValueError(f"Preserving modified demo file: {path}")
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def source_hashes(repository: Path) -> dict[str, str]:
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in repository.glob("*.py")}


def demo_runner():
    from backend.agents.patch_generation_agent import PatchGenerationAgent
    from backend.services.llm.mock_provider import MockLLMProvider
    from backend.services.llm.service import LLMService
    from backend.services.workflows import WorkflowRunner

    def response(messages):
        retrying = "Attempt: #2" in messages[-1].content
        return json.dumps({
            "explanation": "Scripted demo: replace eval with literal_eval" if retrying else "Scripted demo: deliberately fail the behavior tests to demonstrate retry",
            "changes": [{
                "file_path": "app.py", "start_line": 2, "end_line": 2,
                "original_code": "    return eval(expression)",
                "replacement_code": "    import ast\n    return ast.literal_eval(expression)" if retrying else "    return None",
            }],
            "assumptions": ["Inputs are Python literals rather than executable expressions"],
            "tests_to_run": ["test_app.py"],
        })

    generator = PatchGenerationAgent(llm_service=LLMService(provider=MockLLMProvider(
        model="scripted-demo-v1", response_generator=response)))
    return WorkflowRunner(generator=generator)


def run_demo(db, repository: Path):
    from backend.database.models import WorkflowModel
    baseline = source_hashes(repository)
    workflow = WorkflowModel(
        id=f"wf-demo-{uuid.uuid4().hex}", repository_path=str(repository.resolve()),
        status="CREATED", max_retries=1,
        request_json=json.dumps({"max_findings": 10, "minimum_priority": "LOW"}),
    )
    db.add(workflow)
    db.commit()
    demo_runner().run(db, workflow.id)
    if source_hashes(repository) != baseline:
        raise RuntimeError("Demo source changed during candidate validation")
    return workflow


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=".test-artifacts/demo.db",
                        help="SQLite database inside .test-artifacts; never the project database")
    args = parser.parse_args()
    artifacts = (ROOT / ".test-artifacts").resolve()
    database = (ROOT / args.database).resolve()
    if not database.is_relative_to(artifacts) or database.suffix != ".db":
        parser.error("Choose a .db file inside the project's .test-artifacts directory")
    database.parent.mkdir(parents=True, exist_ok=True)
    repository = artifacts / "demo-repository"
    create_demo_repository(repository)

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from backend.database.database import Base, apply_mvp_migrations
    from backend.database import models  # register all mapped tables
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    apply_mvp_migrations(engine)
    try:
        with Session(engine) as db:
            workflow = run_demo(db, repository)
            print(json.dumps({"id": workflow.id, "status": workflow.status,
                              "outcome": workflow.outcome, "errors": workflow.error_message,
                              "database": str(database), "model": "scripted-demo-v1",
                              "dashboard": f"http://127.0.0.1:5173/?workflow={workflow.id}"}, indent=2))
            return 0 if workflow.status == "READY_FOR_REVIEW" else 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
