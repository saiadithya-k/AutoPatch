"""Vulnerable database module containing SQL injection flaw for SAST demonstration."""

import sqlite3
from typing import Any, Optional


def init_demo_db() -> sqlite3.Connection:
    """Initialize in-memory SQLite database for testing."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, role) VALUES ('admin', 'administrator')")
    cursor.execute("INSERT INTO users (username, role) VALUES ('alice', 'user')")
    conn.commit()
    return conn


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[tuple[Any, ...]]:
    """
    VULNERABILITY: Raw SQL string formatting allows SQL Injection (CWE-89).
    Detected by Bandit (B608) and Semgrep (sql-injection).
    """
    cursor = conn.cursor()
    # INSECURE: Formatted string query directly interpolates untrusted user parameter
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
