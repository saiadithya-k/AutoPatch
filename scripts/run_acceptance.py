"""Run reproducible remediation cases, with optional real Docker and Ollama.

Defaults to scripted reference fixes. --live-model explicitly opts into the
configured local Ollama service; it never selects a paid cloud provider.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.acceptance_cases import CASES


def check_prerequisites(*, live_model=False, docker=False, image=None):
    import httpx
    import subprocess
    from backend.config import get_settings
    from backend.tools.sandbox import DockerSandboxExecutor
    settings = get_settings()
    if live_model:
        if settings.LLM_PROVIDER != "ollama":
            raise RuntimeError("Live acceptance requires LLM_PROVIDER=ollama; no cloud calls are made")
        endpoint = (settings.LLM_BASE_URL or "http://localhost:11434/v1").rstrip("/")
        response = httpx.get(endpoint + "/models", timeout=10)
        response.raise_for_status()
        if settings.LLM_MODEL not in [item.get("id") for item in response.json().get("data", [])]:
            raise RuntimeError(f"Configured Ollama model is not installed: {settings.LLM_MODEL}")
    if docker:
        if not DockerSandboxExecutor.is_docker_available():
            raise RuntimeError("Docker was explicitly requested but its daemon is unavailable")
        inspected = subprocess.run(["docker", "image", "inspect", image or settings.DOCKER_IMAGE],
                                   capture_output=True, text=True, timeout=15, shell=False)
        if inspected.returncode:
            raise RuntimeError("Required validator image is missing; build the base and acceptance images first")


def execute_case(case, repository, db, *, live_model=False, sandbox=None, handle_interrupt=False):
    from backend.agents.patch_generation_agent import PatchGenerationAgent
    from backend.agents.retry_agent import RetryAgent
    from backend.agents.scanning_agent import ScanningAgent
    from backend.agents.validation_agent import ValidationAgent
    from backend.config import get_settings
    from backend.database.models import WorkflowModel, utc_now
    from backend.services.llm.mock_provider import MockLLMProvider
    from backend.services.llm.schemas import LLMCodeChange, LLMPatchGeneration
    from backend.services.llm.service import LLMService
    from backend.services.reports import workflow_report
    from backend.services.workflows import WorkflowRunner
    from backend.tools.bandit_runner import BanditRunner
    from backend.tools.sandbox import LocalWorkspaceSandboxExecutor
    from backend.tools.semgrep_runner import SemgrepRunner

    started = time.perf_counter()
    case.materialize(repository)
    original = ValidationAgent._calculate_repo_hashes(repository)
    sandbox = sandbox or LocalWorkspaceSandboxExecutor()
    if live_model:
        generator = PatchGenerationAgent(llm_service=LLMService())
    else:
        # References never enter the repository or a real model's prompt.
        payload = LLMPatchGeneration(explanation=f"Reference remediation for {case.name}", changes=[
            LLMCodeChange(file_path=name, start_line=1, end_line=len(case.files[name].splitlines()),
                          original_code=case.files[name].rstrip("\n"), replacement_code=source.rstrip("\n"))
            for name, source in case.fixed_sources.items()
        ])
        generator = PatchGenerationAgent(llm_service=LLMService(provider=MockLLMProvider(
            model="acceptance-reference-v1", canned_parsed=payload)))
    scanner = ScanningAgent(bandit_runner=BanditRunner(sandbox=sandbox),
                            semgrep_runner=SemgrepRunner(sandbox=sandbox))
    retry = RetryAgent(patch_generation_agent=generator,
                       validation_agent=ValidationAgent(sandbox=sandbox))
    workflow = WorkflowModel(id=f"wf-acceptance-{uuid.uuid4().hex}",
        repository_path=str(repository.resolve()), status="CREATED", max_retries=2 if live_model else 0,
        request_json=json.dumps({"max_findings": 10, "minimum_priority": "LOW"}))
    db.add(workflow)
    db.commit()
    interrupted = False
    try:
        WorkflowRunner(scanner=scanner, generator=generator, retry=retry).run(db, workflow.id)
    except KeyboardInterrupt:
        if not handle_interrupt:
            raise
        interrupted = True
        db.rollback()
        workflow = db.get(WorkflowModel, workflow.id)
        workflow.status = "FAILED"
        workflow.current_stage = "INTERRUPTED"
        workflow.outcome = "INTERRUPTED"
        workflow.completed_at = utc_now()
        workflow.error_message = "Acceptance run interrupted; no candidate was applied to original source"
        workflow.errors_json = json.dumps([workflow.error_message])
        db.commit()
    report = workflow_report(db, workflow)
    unchanged = original == ValidationAgent._calculate_repo_hashes(repository)
    validations = report["validations"]
    ready = [p for p in report["patches"] if p["status"] == "READY_FOR_REVIEW"]
    complete = (workflow.status == "READY_FOR_REVIEW" and workflow.total_findings > 0
                and workflow.processed_findings == workflow.total_findings
                and workflow.reviewable_count == workflow.total_findings and not workflow.failed_count
                and len(ready) == workflow.total_findings and unchanged
                and all(any(v["patch_attempt_id"] == p["id"] and v["status"] == "PASSED"
                            and v["tests_run"] > 0 and v["scanner_metadata"].get("coverage_complete") is True
                            for v in validations) for p in ready))
    settings = get_settings()
    return {"case": case.name, "passed": bool(complete), "interrupted": interrupted, "source_unchanged": unchanged,
            "model": settings.LLM_MODEL if live_model else "acceptance-reference-v1",
            "provider": "ollama" if live_model else "reference", "sandbox": sandbox.sandbox_type,
            "duration_seconds": round(time.perf_counter() - started, 2), "report": report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-model", action="store_true")
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--image", default="autopatch-validator-acceptance:latest")
    parser.add_argument("--case", choices=list(CASES), action="append", dest="cases")
    parser.add_argument("--output", help="New result directory inside .test-artifacts")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    artifacts = (ROOT / ".test-artifacts").resolve()
    output = (ROOT / (args.output or f".test-artifacts/acceptance-{stamp}-{uuid.uuid4().hex[:6]}")).resolve()
    if not artifacts.is_relative_to(ROOT) or not output.is_relative_to(artifacts) or output == artifacts:
        parser.error("Output must be a new directory inside this project's .test-artifacts")
    if output.exists():
        parser.error("Output directory already exists; choose a new directory to preserve prior evidence")
    output.mkdir(parents=True)
    try:
        check_prerequisites(live_model=args.live_model, docker=args.docker, image=args.image)
    except Exception as error:
        (output / "prerequisite-error.json").write_text(json.dumps({"error": str(error)}, indent=2), encoding="utf-8")
        print(f"Acceptance prerequisites failed: {error}", file=sys.stderr)
        return 2
    from fastapi.encoders import jsonable_encoder
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from backend.database.database import Base
    from backend.tools.sandbox import DockerSandboxExecutor
    engine = create_engine(f"sqlite:///{(output / 'evidence.db').as_posix()}")
    Base.metadata.create_all(engine)
    summaries = []
    sandbox = DockerSandboxExecutor(image=args.image, default_timeout=120) if args.docker else None
    try:
        for name in args.cases or CASES:
            print(f"Running {name} ({'ollama' if args.live_model else 'reference'}, {'docker' if args.docker else 'local'})", flush=True)
            with Session(engine) as db:
                result = execute_case(CASES[name], output / name / "repository", db,
                                      live_model=args.live_model, sandbox=sandbox, handle_interrupt=True)
                (output / f"{name}.json").write_text(json.dumps(jsonable_encoder(result), indent=2), encoding="utf-8")
                summary = {key: result[key] for key in ("case", "passed", "source_unchanged", "model", "sandbox", "duration_seconds")}
                summary["errors"] = result["report"]["workflow"]["errors"]
                summary["interrupted"] = result["interrupted"]
                summaries.append(summary)
                (output / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
                print(json.dumps(summary), flush=True)
                if result["interrupted"]:
                    break
    finally:
        engine.dispose()
    (output / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    print(f"Evidence: {output}")
    if any(row["interrupted"] for row in summaries):
        return 130
    return 0 if all(row["passed"] for row in summaries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
