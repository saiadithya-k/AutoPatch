"""Unit tests verifying normal functional behavior of the vulnerable demo project."""

import pytest
try:
    from app import calculate_user_metric, execute_system_diagnostic
    from database import get_user_by_username, init_demo_db
except ImportError:
    from tests.vulnerable_project.app import calculate_user_metric, execute_system_diagnostic
    from tests.vulnerable_project.database import get_user_by_username, init_demo_db


def test_database_get_user_valid():
    conn = init_demo_db()
    user = get_user_by_username(conn, "alice")
    assert user is not None
    assert user[1] == "alice"
    assert user[2] == "user"


def test_database_get_user_not_found():
    conn = init_demo_db()
    user = get_user_by_username(conn, "nonexistent")
    assert user is None


def test_calculate_user_metric():
    result = calculate_user_metric("10 + 20 * 2")
    assert result == 50


def test_execute_system_diagnostic():
    exit_code = execute_system_diagnostic("localhost")
    assert exit_code == 0
