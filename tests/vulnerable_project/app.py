"""Vulnerable application module containing Command Injection and unsafe eval for SAST demonstration."""

import os
import subprocess
from typing import Any


def execute_system_diagnostic(target_host: str) -> int:
    """
    VULNERABILITY: os.system with formatted command string allows Command Injection (CWE-78).
    Detected by Bandit (B605) and Semgrep.
    """
    # INSECURE: Formatted command executed directly via shell
    command = f"echo Running diagnostic for host {target_host}"
    return os.system(command)


def calculate_user_metric(expression_str: str) -> Any:
    """
    VULNERABILITY: Use of built-in eval on untrusted user expression (CWE-95).
    Detected by Bandit (B307) and Semgrep.
    """
    # INSECURE: Dangerous dynamic code evaluation
    return eval(expression_str)
