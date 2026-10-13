"""Report local prerequisites without exposing environment variables or credentials."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def command_ready(command: list[str], timeout: int = 10) -> bool:
    try:
        return subprocess.run(command, capture_output=True, timeout=timeout, shell=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    modules = ["fastapi", "uvicorn", "pydantic_settings", "sqlalchemy", "pytest", "bandit", "semgrep"]
    available = {module: importlib.util.find_spec(module) is not None for module in modules}
    checks: dict = {"python": sys.version.split()[0], "python_supported": sys.version_info[:2] == (3, 11), "dependencies": available}
    if not all(available.values()):
        checks["ready"] = False
        print(json.dumps(checks, indent=2))
        return 1

    from backend.config import get_settings
    settings = get_settings()
    checks["bandit"] = command_ready([sys.executable, "-m", "bandit", "--version"])
    from backend.tools.semgrep_runner import SemgrepRunner
    checks["semgrep"] = command_ready(SemgrepRunner()._resolve_executable() + ["--version"], timeout=30)
    checks["docker"] = command_ready(["docker", "info"])
    checks["sandbox"] = "docker" if settings.DOCKER_ENABLED else "local_workspace_dev_fallback"
    checks["sandbox_ready"] = checks["docker"] if settings.DOCKER_ENABLED else settings.ALLOW_LOCAL_FALLBACK
    checks["model_provider"] = settings.LLM_PROVIDER
    checks["model_ready"] = False
    if settings.LLM_PROVIDER == "mock":
        checks["model_ready"] = True
    elif settings.LLM_PROVIDER == "ollama":
        import httpx
        try:
            endpoint = (settings.LLM_BASE_URL or "http://localhost:11434/v1").rstrip("/")
            response = httpx.get(endpoint + "/models", timeout=5)
            response.raise_for_status()
            checks["model_ready"] = settings.LLM_MODEL in [item.get("id") for item in response.json().get("data", [])]
        except (httpx.HTTPError, ValueError, TypeError):
            pass
    else:
        checks["model_ready"] = bool(settings.OPENAI_API_KEY)
        checks["model_check"] = "Configuration only; no paid request sent."
    checks["ready"] = all(checks[key] for key in ["python_supported", "bandit", "semgrep", "sandbox_ready", "model_ready"])
    print(json.dumps(checks, indent=2))
    return 0 if checks["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
