"""AutoPatch Sandbox Execution Abstraction.

Defines the SandboxExecutor interface and implementations for local isolated workspaces
and secure containerized Docker sandboxes.
Enforces strict network isolation (--network none), unprivileged user execution,
resource limits, and automatic container cleanup.
"""

from abc import ABC, abstractmethod
import logging
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from backend.config import get_settings

logger = logging.getLogger(__name__)


class SandboxExecutionResult:
    """Standardized execution output from a sandbox environment."""

    def __init__(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
        duration: float,
        timed_out: bool = False,
        sandbox_type: str = "local_workspace_dev_fallback",
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.timed_out = timed_out
        self.sandbox_type = sandbox_type


class SandboxSecurityError(Exception):
    """Raised when a sandbox execution command violates security policies."""
    pass


class DockerRequiredError(Exception):
    """Raised when Docker execution is required but the Docker daemon is unavailable."""
    pass


class SandboxExecutor(ABC):
    """Abstract interface for executing validation commands in an isolated sandbox."""

    @property
    @abstractmethod
    def sandbox_type(self) -> str:
        """Identifier of the sandbox type (e.g. 'docker' or 'local_workspace_dev_fallback')."""
        pass

    @abstractmethod
    def run_command(
        self,
        cmd: list[str],
        cwd: Path,
        timeout: Optional[int] = None,
    ) -> SandboxExecutionResult:
        """Execute a controlled command inside the sandbox."""
        pass


class LocalWorkspaceSandboxExecutor(SandboxExecutor):
    """
    Executes controlled validation commands directly inside an isolated temporary directory.
    Clearly labeled as development fallback; NOT the production sandbox.
    """

    def __init__(self, default_timeout: int = 60):
        self.default_timeout = default_timeout

    @property
    def sandbox_type(self) -> str:
        return "local_workspace_dev_fallback"

    def run_command(
        self,
        cmd: list[str],
        cwd: Path,
        timeout: Optional[int] = None,
    ) -> SandboxExecutionResult:
        """Execute subprocess within the specified isolated directory with strict shell=False."""
        actual_timeout = timeout or self.default_timeout
        start_time = time.perf_counter()

        try:
            res = subprocess.run(
                cmd,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                timeout=actual_timeout,
                shell=False,  # MANDATORY SECURITY GUARD
            )
            duration = time.perf_counter() - start_time
            return SandboxExecutionResult(
                exit_code=res.returncode,
                stdout=res.stdout or "",
                stderr=res.stderr or "",
                duration=round(duration, 3),
                timed_out=False,
                sandbox_type=self.sandbox_type,
            )
        except subprocess.TimeoutExpired as e:
            duration = time.perf_counter() - start_time
            return SandboxExecutionResult(
                exit_code=-1,
                stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
                stderr=f"Command timed out after {actual_timeout}s.",
                duration=round(duration, 3),
                timed_out=True,
                sandbox_type=self.sandbox_type,
            )
        except Exception as e:
            duration = time.perf_counter() - start_time
            return SandboxExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Command execution error: {str(e)}",
                duration=round(duration, 3),
                timed_out=False,
                sandbox_type=self.sandbox_type,
            )


class DockerSandboxExecutor(SandboxExecutor):
    """
    Executes validation commands inside an isolated Docker container with:
    - --network none (strict network isolation)
    - Non-root user (10001:10001)
    - Ephemeral container (--rm)
    - Capability drop (--cap-drop=ALL)
    - No new privileges (--security-opt no-new-privileges)
    - Read/write access strictly limited to /workspace
    - Resource controls (memory, CPU, PID limits)
    """

    def __init__(
        self,
        image: Optional[str] = None,
        default_timeout: Optional[int] = None,
        memory_limit: Optional[str] = None,
        cpu_limit: Optional[str] = None,
        pids_limit: Optional[int] = None,
        fail_closed: bool = True,
    ):
        settings = get_settings()
        self.image = image or settings.DOCKER_IMAGE
        self.default_timeout = default_timeout or settings.DOCKER_TIMEOUT
        self.memory_limit = memory_limit or settings.DOCKER_MEMORY_LIMIT
        self.cpu_limit = cpu_limit or settings.DOCKER_CPU_LIMIT
        self.pids_limit = pids_limit or settings.DOCKER_PIDS_LIMIT
        self.fail_closed = fail_closed

    @property
    def sandbox_type(self) -> str:
        return "docker"

    @classmethod
    def is_docker_available(cls) -> bool:
        """Check whether the docker binary is installed and the daemon is reachable."""
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False
        try:
            res = subprocess.run(
                [docker_bin, "info"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    def build_docker_command(self, cmd: list[str], cwd: Path, container_name: str) -> list[str]:
        """
        Construct the secure docker run argument list.
        Never uses shell=True.
        """
        norm_cwd = str(cwd.resolve()).replace("\\", "/")
        # Build argument list
        docker_cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network", "none",  # Strict network isolation
            "--user", "10001:10001",  # Non-root user
            "--cap-drop=ALL",  # Drop all Linux capabilities
            "--security-opt", "no-new-privileges",
            "-v", f"{norm_cwd}:/workspace:rw",
            "-w", "/workspace",
            "--memory", self.memory_limit,
            "--cpus", str(self.cpu_limit),
            "--pids-limit", str(self.pids_limit),
            self.image,
        ] + cmd

        self.validate_command_security(docker_cmd, cwd)
        return docker_cmd

    @classmethod
    def validate_command_security(cls, docker_cmd: list[str], cwd: Path) -> None:
        """
        Validate that the constructed docker command enforces all critical security guarantees.
        """
        # 1. Enforce network none
        if "--network" not in docker_cmd:
            raise SandboxSecurityError("Docker command missing --network argument.")
        net_idx = docker_cmd.index("--network")
        if net_idx + 1 >= len(docker_cmd) or docker_cmd[net_idx + 1] != "none":
            raise SandboxSecurityError("Docker command must enforce --network none.")

        # 2. Reject privileged execution
        if "--privileged" in docker_cmd:
            raise SandboxSecurityError("Privileged Docker execution is strictly forbidden.")

        # 3. Reject Docker socket mounting
        for arg in docker_cmd:
            if "docker.sock" in arg:
                raise SandboxSecurityError("Mounting docker.sock is strictly forbidden.")

        # 4. Reject host PID namespace
        if "--pid" in docker_cmd and "host" in docker_cmd:
            raise SandboxSecurityError("Host PID namespace is strictly forbidden.")

        # 5. Validate volume mounts: only the specified cwd mounted to /workspace
        cwd_resolved = str(cwd.resolve()).replace("\\", "/").lower()
        for i, arg in enumerate(docker_cmd):
            if arg in ("-v", "--volume") and i + 1 < len(docker_cmd):
                mount_spec = docker_cmd[i + 1]
                # Windows paths have colons (e.g. C:/Users/...). Split from right.
                rparts = mount_spec.rsplit(":", 2)
                if len(rparts) == 3 and rparts[2] in ("ro", "rw"):
                    host_path = rparts[0].replace("\\", "/").lower()
                    dest_path = rparts[1]
                elif len(rparts) >= 2:
                    host_path = mount_spec.rsplit(":", 1)[0].replace("\\", "/").lower()
                    dest_path = mount_spec.rsplit(":", 1)[1]
                else:
                    host_path = mount_spec
                    dest_path = ""

                if dest_path != "/workspace":
                    raise SandboxSecurityError(f"Unauthorized container mount destination '{dest_path}'. Must be /workspace.")
                if host_path != cwd_resolved:
                    raise SandboxSecurityError(f"Unauthorized host mount path '{host_path}'. Must match workspace '{cwd_resolved}'.")

    def run_command(
        self,
        cmd: list[str],
        cwd: Path,
        timeout: Optional[int] = None,
    ) -> SandboxExecutionResult:
        """
        Run command inside an isolated Docker container with strict network isolation,
        capability dropping, and resource limits.
        """
        actual_timeout = timeout or self.default_timeout

        if not self.is_docker_available():
            msg = "Docker sandbox required but unavailable (docker daemon not reachable)."
            logger.error(msg)
            if self.fail_closed:
                raise DockerRequiredError(msg)
            return SandboxExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=msg,
                duration=0.0,
                timed_out=False,
                sandbox_type=self.sandbox_type,
            )

        container_name = f"autopatch_val_{uuid.uuid4().hex[:12]}"
        docker_cmd = self.build_docker_command(cmd, cwd, container_name)

        logger.info("Executing in Docker (%s): %s", container_name, " ".join(docker_cmd))
        start_time = time.perf_counter()

        try:
            process = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=actual_timeout,
                shell=False,  # MANDATORY SECURITY GUARD
            )
            duration = time.perf_counter() - start_time
            return SandboxExecutionResult(
                exit_code=process.returncode,
                stdout=process.stdout or "",
                stderr=process.stderr or "",
                duration=round(duration, 3),
                timed_out=False,
                sandbox_type=self.sandbox_type,
            )

        except subprocess.TimeoutExpired as e:
            duration = time.perf_counter() - start_time
            logger.warning("Docker execution timed out after %ds for container %s. Killing...", actual_timeout, container_name)
            # Deterministic container cleanup on timeout
            try:
                subprocess.run(
                    ["docker", "kill", container_name],
                    capture_output=True,
                    timeout=10,
                    shell=False,
                )
            except Exception as cleanup_err:
                logger.warning("Failed to kill container %s: %s", container_name, cleanup_err)

            return SandboxExecutionResult(
                exit_code=-1,
                stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
                stderr=f"Docker execution timed out after {actual_timeout} seconds.",
                duration=round(duration, 3),
                timed_out=True,
                sandbox_type=self.sandbox_type,
            )

        except Exception as e:
            duration = time.perf_counter() - start_time
            logger.error("Docker command execution error: %s", e)
            return SandboxExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Docker execution failure: {str(e)}",
                duration=round(duration, 3),
                timed_out=False,
                sandbox_type=self.sandbox_type,
            )


def get_default_sandbox_executor() -> SandboxExecutor:
    """
    Factory function to instantiate the configured sandbox executor.
    If DOCKER_ENABLED is True, returns DockerSandboxExecutor (which fails closed if unavailable).
    Otherwise returns LocalWorkspaceSandboxExecutor.
    """
    settings = get_settings()
    if settings.DOCKER_ENABLED:
        return DockerSandboxExecutor(
            image=settings.DOCKER_IMAGE,
            default_timeout=settings.DOCKER_TIMEOUT,
            memory_limit=settings.DOCKER_MEMORY_LIMIT,
            cpu_limit=settings.DOCKER_CPU_LIMIT,
            pids_limit=settings.DOCKER_PIDS_LIMIT,
            fail_closed=True,
        )
    if not settings.ALLOW_LOCAL_FALLBACK:
        raise DockerRequiredError(
            "Local execution is disabled by ALLOW_LOCAL_FALLBACK=False; enable Docker isolation."
        )
    return LocalWorkspaceSandboxExecutor(default_timeout=settings.TEST_TIMEOUT)
