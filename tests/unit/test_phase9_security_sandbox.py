"""Phase 9 Security & Sandbox Verification Test Suite.

Exhaustively verifies Part 19 requirements A through Y:
A. Docker command construction
B. --network none
C. non-root execution
D. capability dropping
E. workspace-only mount
F. original repository not mounted
G. no docker socket mount
H. timeout
I. container cleanup
J. patch traversal
K. absolute path
L. Windows drive path
M. UNC path
N. symlink escape
O. malformed unified diff
P. incorrect hunk counts
Q. partial patch failure atomicity
R. syntax error
S. test failure
T. scanner failure
U. unresolved vulnerability
V. new vulnerability
W. successful validation
X. original repository immutability
Y. API returns exact stored validation evidence
"""

import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.agents.validation_agent import ValidationAgent
from backend.database.models import (
    PatchAttemptModel,
    RiskAssessmentModel,
    ValidationResultModel,
    VulnerabilityModel,
    WorkflowModel,
)
from backend.main import app
from backend.models.patch import PatchStatus
from backend.models.validation import ValidationResult, ValidationStatus
from backend.models.vulnerability import (
    Confidence,
    Severity,
    VulnerabilityFinding,
    VulnerabilityStatus,
)
from backend.tools.patch_applier import PatchApplicationError, PatchApplier
from backend.tools.sandbox import (
    DockerRequiredError,
    DockerSandboxExecutor,
    LocalWorkspaceSandboxExecutor,
    SandboxExecutionResult,
    SandboxSecurityError,
)
from backend.tools.test_runner import TestResult, TestRunner
from backend.tools.workspace import TemporaryWorkspace


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "test_repo"
    repo.mkdir(parents=True, exist_ok=True)
    app_py = repo / "app.py"
    app_py.write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")
    return repo


@pytest.fixture
def sample_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id="vuln-p9-001",
        workflow_id="wf-p9",
        tool="bandit",
        rule_id="B602",
        type="Subprocess Popen with shell=True",
        cwe="CWE-78",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_start=2,
        line_end=2,
        code_snippet="return cmd",
        description="Potential command injection",
        status=VulnerabilityStatus.PRIORITIZED,
    )


# ---------------------------------------------------------------------------
# A. Docker Command Construction
# ---------------------------------------------------------------------------

def test_a_docker_command_construction(tmp_path: Path):
    executor = DockerSandboxExecutor(
        image="autopatch-validator:test",
        memory_limit="256m",
        cpu_limit="0.5",
        pids_limit=50,
    )
    cmd = ["python", "-m", "pytest", "-q"]
    docker_cmd = executor.build_docker_command(cmd, tmp_path, "test_container")

    assert docker_cmd[0] == "docker"
    assert docker_cmd[1] == "run"
    assert "--rm" in docker_cmd
    assert "--name" in docker_cmd and "test_container" in docker_cmd
    assert "--memory" in docker_cmd and "256m" in docker_cmd
    assert "--cpus" in docker_cmd and "0.5" in docker_cmd
    assert "--pids-limit" in docker_cmd and "50" in docker_cmd
    assert "autopatch-validator:test" in docker_cmd
    assert docker_cmd[-4:] == ["python", "-m", "pytest", "-q"]


# ---------------------------------------------------------------------------
# B. --network none Enforcement
# ---------------------------------------------------------------------------

def test_b_network_none_enforcement(tmp_path: Path):
    executor = DockerSandboxExecutor()
    cmd = executor.build_docker_command(["python"], tmp_path, "c1")
    assert "--network" in cmd
    net_idx = cmd.index("--network")
    assert cmd[net_idx + 1] == "none"

    # Verify tampering with network raises SandboxSecurityError
    tampered = list(cmd)
    tampered[net_idx + 1] = "host"
    with pytest.raises(SandboxSecurityError, match="must enforce --network none"):
        executor.validate_command_security(tampered, tmp_path)


# ---------------------------------------------------------------------------
# C. Non-root Execution
# ---------------------------------------------------------------------------

def test_c_non_root_execution(tmp_path: Path):
    executor = DockerSandboxExecutor()
    cmd = executor.build_docker_command(["python"], tmp_path, "c1")
    assert "--user" in cmd
    user_idx = cmd.index("--user")
    assert cmd[user_idx + 1] == "10001:10001"


# ---------------------------------------------------------------------------
# D. Capability Dropping & No New Privileges
# ---------------------------------------------------------------------------

def test_d_capability_dropping(tmp_path: Path):
    executor = DockerSandboxExecutor()
    cmd = executor.build_docker_command(["python"], tmp_path, "c1")
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt" in cmd
    sec_idx = cmd.index("--security-opt")
    assert cmd[sec_idx + 1] == "no-new-privileges"


# ---------------------------------------------------------------------------
# E. Workspace-only Mount
# ---------------------------------------------------------------------------

def test_e_workspace_only_mount(tmp_path: Path):
    executor = DockerSandboxExecutor()
    cmd = executor.build_docker_command(["python"], tmp_path, "c1")
    v_idx = cmd.index("-v")
    mount_arg = cmd[v_idx + 1]
    assert mount_arg.endswith(":/workspace:rw")

    # Unauthorized destination
    tampered = list(cmd)
    tampered[v_idx + 1] = f"{tmp_path}:/etc:rw"
    with pytest.raises(SandboxSecurityError, match="Must be /workspace"):
        executor.validate_command_security(tampered, tmp_path)


# ---------------------------------------------------------------------------
# F. Original Repository Not Mounted
# ---------------------------------------------------------------------------

def test_f_original_repository_not_mounted(tmp_path: Path):
    executor = DockerSandboxExecutor()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    host_repo = tmp_path / "host_repo"
    host_repo.mkdir()

    cmd = executor.build_docker_command(["python"], workspace, "c1")

    # Verify host_repo path does not appear in any mount argument
    for arg in cmd:
        assert str(host_repo.resolve()) not in arg


# ---------------------------------------------------------------------------
# G. No Docker Socket Mount
# ---------------------------------------------------------------------------

def test_g_no_docker_socket_mount(tmp_path: Path):
    executor = DockerSandboxExecutor()
    cmd = executor.build_docker_command(["python"], tmp_path, "c1")
    assert not any("docker.sock" in arg for arg in cmd)

    # Attempting to mount docker socket throws SandboxSecurityError
    tampered = list(cmd) + ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
    with pytest.raises(SandboxSecurityError, match="docker.sock is strictly forbidden"):
        executor.validate_command_security(tampered, tmp_path)


# ---------------------------------------------------------------------------
# H. Timeout Handling
# ---------------------------------------------------------------------------

def test_h_timeout_handling(tmp_path: Path):
    executor = DockerSandboxExecutor(default_timeout=1)
    with patch("backend.tools.sandbox.DockerSandboxExecutor.is_docker_available", return_value=True), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["docker"], timeout=1)):
        res = executor.run_command(["sleep", "10"], cwd=tmp_path)
        assert res.timed_out is True
        assert res.exit_code == -1
        assert "timed out" in res.stderr.lower()


# ---------------------------------------------------------------------------
# I. Container Cleanup on Timeout
# ---------------------------------------------------------------------------

def test_i_container_cleanup_on_timeout(tmp_path: Path):
    executor = DockerSandboxExecutor(default_timeout=1)
    killed_containers = []

    def mock_subprocess(cmd, **kwargs):
        if cmd[:3] == ["docker", "rm", "-f"]:
            killed_containers.append(cmd[3])
            return MagicMock(returncode=0)
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    with patch("backend.tools.sandbox.DockerSandboxExecutor.is_docker_available", return_value=True), \
         patch("subprocess.run", side_effect=mock_subprocess):
        res = executor.run_command(["sleep", "10"], cwd=tmp_path)
        assert res.timed_out is True
        assert len(killed_containers) == 1
        assert killed_containers[0].startswith("autopatch_val_")


# ---------------------------------------------------------------------------
# J. Patch Traversal Rejection
# ---------------------------------------------------------------------------

def test_j_patch_traversal_rejection(tmp_path: Path):
    diff = """--- a/../secret.py
+++ b/../secret.py
@@ -1,1 +1,1 @@
-old
+new"""
    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "traversal" in err.lower()


# ---------------------------------------------------------------------------
# K. Absolute Path Rejection
# ---------------------------------------------------------------------------

def test_k_patch_absolute_path_rejection(tmp_path: Path):
    diff = """--- a//etc/shadow
+++ b//etc/shadow
@@ -1,1 +1,1 @@
-old
+new"""
    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "absolute path" in err.lower()


# ---------------------------------------------------------------------------
# L. Windows Drive Path Rejection
# ---------------------------------------------------------------------------

def test_l_windows_drive_path_rejection(tmp_path: Path):
    diff = """--- a/C:/Windows/win.ini
+++ b/C:/Windows/win.ini
@@ -1,1 +1,1 @@
-old
+new"""
    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "drive-letter" in err.lower() or "absolute" in err.lower()


# ---------------------------------------------------------------------------
# M. UNC Path Rejection
# ---------------------------------------------------------------------------

def test_m_unc_path_rejection(tmp_path: Path):
    diff = """--- a/\\\\server\\share\\data.py
+++ b/\\\\server\\share\\data.py
@@ -1,1 +1,1 @@
-old
+new"""
    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "unc path" in err.lower()


# ---------------------------------------------------------------------------
# N. Symlink Escape Rejection
# ---------------------------------------------------------------------------

def test_n_symlink_escape_rejection(tmp_path: Path):
    ws = tmp_path / "ws"
    ws.mkdir()
    link_file = ws / "link.py"
    link_file.write_text("secret = 1\n", encoding="utf-8")

    diff = """--- a/link.py
+++ b/link.py
@@ -1,1 +1,1 @@
-secret = 1
+secret = 2"""

    # Mock symlink resolution pointing outside workspace boundary
    outside_path = (tmp_path / "outside.py").resolve()
    with patch.object(Path, "is_symlink", return_value=True), \
         patch.object(Path, "resolve", return_value=outside_path):
        applied, err = PatchApplier.apply_patch(ws, diff)
        assert applied is False
        assert "symlink" in err.lower() or "escapes" in err.lower()


# ---------------------------------------------------------------------------
# O. Malformed Unified Diff
# ---------------------------------------------------------------------------

def test_o_malformed_unified_diff(tmp_path: Path):
    diff = "This is not a valid unified diff"
    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "no valid file diff headers" in err.lower()


# ---------------------------------------------------------------------------
# P. Incorrect Hunk Counts
# ---------------------------------------------------------------------------

def test_p_incorrect_hunk_counts(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text("line1\nline2\n", encoding="utf-8")

    # Header claims 50 lines, but only 1 provided
    diff = """--- a/app.py
+++ b/app.py
@@ -1,50 +1,1 @@
-line1
+line1_modified"""
    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False
    assert "header counts" in err.lower() and "do not match" in err.lower()


# ---------------------------------------------------------------------------
# Q. Partial Patch Failure Atomicity
# ---------------------------------------------------------------------------

def test_q_partial_patch_failure_atomicity(tmp_path: Path):
    file1 = tmp_path / "f1.py"
    file1.write_text("hello world\n", encoding="utf-8")
    file2 = tmp_path / "f2.py"
    file2.write_text("foo bar\n", encoding="utf-8")

    # Hunk 1 matches file1, but Hunk 2 does not match file2
    diff = """--- a/f1.py
+++ b/f1.py
@@ -1,1 +1,1 @@
-hello world
+hello safe
--- a/f2.py
+++ b/f2.py
@@ -1,1 +1,1 @@
-nonexistent content that fails
+replacement"""

    applied, err = PatchApplier.apply_patch(tmp_path, diff)
    assert applied is False

    # Atomicity: file1 must NOT have been modified!
    assert file1.read_text(encoding="utf-8") == "hello world\n"


# ---------------------------------------------------------------------------
# R. Syntax Error Causes Validation Failure
# ---------------------------------------------------------------------------

def test_r_syntax_error_failure(temp_repo: Path, sample_finding: VulnerabilityFinding):
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return def invalid syntax"""

    agent = ValidationAgent()
    res = agent.execute_validation(
        patch_id="patch-syn",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )
    assert res.status == ValidationStatus.FAILED
    assert res.syntax_check_passed is False
    assert "syntax check failed" in res.failure_reason.lower()


# ---------------------------------------------------------------------------
# S. Test Failure Causes Validation Failure
# ---------------------------------------------------------------------------

def test_s_test_failure(temp_repo: Path, sample_finding: VulnerabilityFinding):
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return "broke tests" """

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(
        success=False,
        exit_code=1,
        command=["pytest"],
        duration=0.2,
        tests_passed=0,
        tests_failed=1,
        error_message="1 test failed",
    )

    scanner = MagicMock()
    scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True})
    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=scanner)
    res = agent.execute_validation(
        patch_id="patch-test-fail",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )
    assert res.status == ValidationStatus.FAILED
    assert res.tests_passed is False
    assert res.regression_detected is True


# ---------------------------------------------------------------------------
# T. Scanner Failure Handling
# ---------------------------------------------------------------------------

def test_t_scanner_failure(temp_repo: Path, sample_finding: VulnerabilityFinding):
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return "safe" """

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1)

    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([], {"scan_status": "FAILED", "errors": ["Scanner crashed"]})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    res = agent.execute_validation(
        patch_id="patch-scan-fail",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )
    assert res.status == ValidationStatus.ERROR
    assert res.security_scan_passed is False
    assert "security re-scan failed" in res.failure_reason.lower()


# ---------------------------------------------------------------------------
# U. Unresolved Vulnerability
# ---------------------------------------------------------------------------

def test_u_unresolved_vulnerability(temp_repo: Path, sample_finding: VulnerabilityFinding):
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return cmd # untouched"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1)

    # Scanner still reports the finding
    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([sample_finding], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    res = agent.execute_validation(
        patch_id="patch-unresolved",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )
    assert res.status == ValidationStatus.FAILED
    assert res.original_vulnerability_resolved is False


# ---------------------------------------------------------------------------
# V. New Vulnerability Introduced
# ---------------------------------------------------------------------------

def test_v_new_vulnerability_introduced(temp_repo: Path, sample_finding: VulnerabilityFinding):
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return eval(cmd)"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1)

    new_finding = VulnerabilityFinding(
        id="vuln-new-002",
        workflow_id="wf-p9",
        tool="bandit",
        rule_id="B307",
        type="Use of eval",
        file_path="app.py",
        severity=Severity.HIGH,
        description="eval is dangerous",
        status=VulnerabilityStatus.PRIORITIZED,
    )

    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([new_finding], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    res = agent.execute_validation(
        patch_id="patch-new-vuln",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )
    assert res.status == ValidationStatus.FAILED
    assert res.new_findings_count == 1
    assert res.security_scan_passed is False


# ---------------------------------------------------------------------------
# W. Successful Validation
# ---------------------------------------------------------------------------

def test_w_successful_validation(temp_repo: Path, sample_finding: VulnerabilityFinding):
    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return str(cmd).strip()"""

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(
        success=True,
        exit_code=0,
        command=["pytest"],
        duration=0.1,
        tests_passed=2,
    )

    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    res = agent.execute_validation(
        patch_id="patch-success",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )
    assert res.status == ValidationStatus.PASSED
    assert res.patch_applied is True
    assert res.syntax_check_passed is True
    assert res.tests_passed is True
    assert res.original_vulnerability_resolved is True
    assert res.new_findings_count == 0
    assert res.security_scan_passed is True


# ---------------------------------------------------------------------------
# X. Original Repository Immutability
# ---------------------------------------------------------------------------

def test_x_original_repository_immutability(temp_repo: Path, sample_finding: VulnerabilityFinding):
    app_py = temp_repo / "app.py"
    initial_content = app_py.read_text(encoding="utf-8")
    initial_hash = hashlib.sha256(initial_content.encode("utf-8")).hexdigest()

    diff = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def run(cmd):
-    return cmd
+    return "safe" """

    mock_runner = MagicMock(spec=TestRunner)
    mock_runner.run_tests.return_value = TestResult(success=True, exit_code=0, command=["pytest"], duration=0.1)

    mock_scanner = MagicMock()
    mock_scanner.scan.return_value = ([], {"scan_status": "COMPLETED", "coverage_complete": True, "errors": []})
    mock_scanner.scan_repository.return_value = mock_scanner.scan.return_value

    agent = ValidationAgent(test_runner=mock_runner, scanning_agent=mock_scanner)
    agent.execute_validation(
        patch_id="patch-immut",
        vulnerability=sample_finding,
        unified_diff=diff,
        repository_path=temp_repo,
        persist=False,
    )

    # Assert byte-for-byte immutability of host repository
    final_content = app_py.read_text(encoding="utf-8")
    final_hash = hashlib.sha256(final_content.encode("utf-8")).hexdigest()
    assert initial_hash == final_hash
    assert initial_content == final_content


# ---------------------------------------------------------------------------
# Y. API Returns Exact Stored Validation Evidence
# ---------------------------------------------------------------------------

def test_y_api_returns_exact_stored_validation_evidence(client, db_session):
    # Setup DB records with exact, non-default evidence
    patch_attempt = PatchAttemptModel(
        id="patch-api-ev",
        workflow_id="wf-1",
        vulnerability_id="vuln-1",
        patch_content="--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-old\n+new",
        status=PatchStatus.VALIDATED.value,
    )
    new_findings_sample = [{"id": "new-1", "tool": "bandit", "rule_id": "B101"}]
    val_model = ValidationResultModel(
        id="val-api-ev",
        patch_attempt_id="patch-api-ev",
        status=ValidationStatus.PASSED.value,
        patch_applied=True,
        syntax_check_passed=True,
        tests_passed=True,
        tests_run=5,
        test_exit_code=0,
        test_stdout="5 passed in 0.10s",
        test_stderr="",
        security_scan_passed=True,
        original_vulnerability_resolved=True,
        new_findings_count=1,
        new_findings=json.dumps(new_findings_sample),
        regression_detected=False,
        failure_reason=None,
        validation_logs="Test logs",
        sandbox_type="local_workspace_dev_fallback",
        duration=1.234,
    )
    db_session.add_all([patch_attempt, val_model])
    db_session.commit()

    # 1. GET /api/patches/{patch_id}/validation
    resp1 = client.get("/api/patches/patch-api-ev/validation")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["syntax_check_passed"] is True
    assert data1["new_findings_count"] == 1
    assert len(data1["new_findings"]) == 1
    assert data1["new_findings"][0]["id"] == "new-1"
    assert data1["duration"] == 1.234
    assert data1["sandbox_type"] == "local_workspace_dev_fallback"

    # 2. GET /api/validations/{validation_id}
    resp2 = client.get("/api/validations/val-api-ev")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["syntax_check_passed"] is True
    assert data2["new_findings_count"] == 1
    assert data2["new_findings"][0]["rule_id"] == "B101"
    assert data2["duration"] == 1.234
