"""Actual containers: isolation, offline scanners, tests and immutable source."""
import json
import os

import pytest

from backend.tools.sandbox import DockerSandboxExecutor
from scripts.acceptance_cases import CASES, AcceptanceCase, SQL, DEPENDENCY
from scripts.run_acceptance import check_prerequisites, execute_case

pytestmark = pytest.mark.docker


@pytest.fixture(scope="session")
def docker_validator(request):
    image = request.config.getoption("--validator-image")
    check_prerequisites(docker=True, image=image)
    return DockerSandboxExecutor(image=image, default_timeout=120)


def test_container_has_no_network_or_privileges(docker_validator, tmp_path):
    code = (
        "import json,os,sys; "
        "status=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line); "
        "print(json.dumps({'uid':os.getuid(),'version':list(sys.version_info[:2]),"
        "'interfaces':os.listdir('/sys/class/net'),'caps':status['CapEff'].strip(),"
        "'no_new_privs':status['NoNewPrivs'].strip(),'docker_socket':os.path.exists('/var/run/'+'docker'+'.sock')}))"
    )
    result = docker_validator.run_command(["python", "-c", code], cwd=tmp_path)
    assert result.exit_code == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["version"] == [3, 11]
    assert evidence["uid"] == 10001
    assert evidence["interfaces"] == ["lo"]
    assert int(evidence["caps"], 16) == 0
    assert evidence["no_new_privs"] == "1"
    assert not evidence["docker_socket"]


@pytest.mark.skipif(os.name != "posix", reason="Native Linux bind-mount ownership")
def test_nonroot_container_can_write_and_host_can_remove_workspace(docker_validator, tmp_path):
    import stat
    from backend.tools.workspace import TemporaryWorkspace
    repository = tmp_path / "private-source"
    repository.mkdir(mode=0o700)
    source = repository / "app.py"
    source.write_text("value = 1\n")
    source.chmod(0o600)
    with TemporaryWorkspace(repository, container_access=True) as workspace:
        result = docker_validator.run_command(["python", "-c",
            "from pathlib import Path; assert Path('app.py').read_text() == 'value = 1\\n'; "
            "Path('generated/deep').mkdir(parents=True); Path('generated/deep/result').write_text('ok')"], cwd=workspace)
        assert result.exit_code == 0, result.stderr
        assert (workspace / "generated/deep/result").read_text() == "ok"
    assert not workspace.exists(), "Container-created files prevented workspace cleanup"
    assert source.read_text() == "value = 1\n"
    assert stat.S_IMODE(source.stat().st_mode) == 0o600


@pytest.mark.parametrize("name", CASES)
def test_real_docker_remediation(name, docker_validator, tmp_path, db_session):
    result = execute_case(CASES[name], tmp_path / name, db_session, sandbox=docker_validator)
    assert result["passed"], result["report"]["workflow"]["errors"]
    assert all(v["sandbox_type"] == "docker" for v in result["report"]["validations"])


def test_docker_timeout_removes_its_container(docker_validator, tmp_path):
    import subprocess
    import uuid
    token = uuid.uuid4().hex
    name = f"autopatch_val_{token[:12]}"
    from unittest.mock import patch
    # Only the random name is controlled; the timeout, Docker process and cleanup are real.
    with patch("backend.tools.sandbox.uuid.uuid4", return_value=type("ID", (), {"hex": token})()):
        result = docker_validator.run_command(["python", "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout=3)
    assert result.timed_out
    inspection = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=^/{name}$"],
                                capture_output=True, text=True, timeout=10, shell=False)
    assert inspection.returncode == 0, inspection.stderr
    assert not inspection.stdout.strip(), "Timed-out validation container leaked"


def test_missing_image_fails_without_a_registry_pull(docker_validator, tmp_path):
    import uuid
    from backend.tools.sandbox import DockerRequiredError
    executor = DockerSandboxExecutor(image=f"autopatch-intentionally-missing:{uuid.uuid4().hex}")
    with pytest.raises(DockerRequiredError, match="could not start the required validator"):
        executor.run_command(["python", "-c", "print('must not run')"], cwd=tmp_path)


@pytest.mark.parametrize("failure", ["syntax", "behavior", "unresolved", "missing_dependency"])
def test_real_docker_rejects_bad_candidates(failure, docker_validator, tmp_path, db_session):
    if failure == "syntax":
        case = AcceptanceCase(failure, SQL.files, {"app.py": "def find_user(connection, username)\n    return None\n"})
    elif failure == "behavior":
        case = AcceptanceCase(failure, SQL.files, {"app.py": "def find_user(connection, username):\n    return None\n"})
    elif failure == "unresolved":
        case = AcceptanceCase(failure, DEPENDENCY.files,
                              {"app.py": DEPENDENCY.files["app.py"] + "\n# A comment does not fix eval.\n"})
    else:
        missing = "_autopatch_missing_dependency_729c"
        files = {**DEPENDENCY.files, "app.py": DEPENDENCY.files["app.py"].replace("import httpx", f"import {missing}")}
        fixed = {"app.py": DEPENDENCY.fixed_sources["app.py"].replace("import httpx", f"import {missing}")}
        case = AcceptanceCase(failure, files, fixed)
    result = execute_case(case, tmp_path / failure, db_session, sandbox=docker_validator)
    assert not result["passed"]
    assert result["source_unchanged"]
    assert result["report"]["workflow"]["reviewable_count"] == 0
    expected = {"syntax": "SYNTAX_ERROR", "behavior": "TEST_FAILURE", "unresolved": "UNRESOLVED_VULNERABILITY", "missing_dependency": "INFRASTRUCTURE_FAILURE"}[failure]
    evidence = result["report"]["validations"]
    assert evidence
    assert all(v["failure_category"] == expected and v["status"] != "PASSED" for v in evidence)
