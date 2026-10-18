"""Controlled repositories for model, scanner and Docker acceptance checks.

Reference fixes are used only by deterministic tests. Live generation sees the
vulnerable files and behavior tests, never these reference fixes.
"""
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AcceptanceCase:
    name: str
    files: dict[str, str]
    fixed_sources: dict[str, str]

    def materialize(self, root: Path) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        for name, content in self.files.items():
            path = root / name
            if path.exists() and path.read_text(encoding="utf-8") != content:
                raise ValueError(f"Preserving changed acceptance source: {path}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root


SQL_TESTS = '''import sqlite3
import unittest
from app import find_user

class TestUsers(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute("CREATE TABLE users (name TEXT)")
        self.connection.executemany("INSERT INTO users VALUES (?)", [("admin",), ("alice",)])

    def tearDown(self):
        self.connection.close()

    def test_existing_user(self):
        self.assertEqual(find_user(self.connection, "alice"), ("alice",))

    def test_unknown_user(self):
        self.assertIsNone(find_user(self.connection, "unknown"))

    def test_injection_is_literal_data(self):
        self.assertIsNone(find_user(self.connection, "alice' OR 1=1 --"))
'''

COMMAND = AcceptanceCase("command_injection", {
    "app.py": '''import os

def display_diagnostic(host):
    """Display a diagnostic label and return zero; no external tool is required."""
    command = f"echo Diagnostic for {host}"
    return os.system(command)
''',
    "test_app.py": '''import unittest
from app import display_diagnostic

class TestDiagnostic(unittest.TestCase):
    def test_host(self):
        self.assertEqual(display_diagnostic("local"), 0)

    def test_empty_host(self):
        self.assertEqual(display_diagnostic(""), 0)
''',
}, {"app.py": '''def display_diagnostic(host):
    """Display a diagnostic label and return zero; no external tool is required."""
    print(f"Diagnostic for {host}")
    return 0
'''})

SQL = AcceptanceCase("sql_injection", {
    "app.py": '''def find_user(connection, username):
    """Look up a username as literal data, returning a row or None."""
    query = f"SELECT name FROM users WHERE name = '{username}'"
    return connection.execute(query).fetchone()
''',
    "test_app.py": SQL_TESTS,
}, {"app.py": '''def find_user(connection, username):
    """Look up a username as literal data, returning a row or None."""
    return connection.execute("SELECT name FROM users WHERE name = ?", (username,)).fetchone()
'''})

MULTIFILE = AcceptanceCase("multifile_sql", {
    "app.py": '''from query_builder import build_query

def find_user(connection, username):
    """Look up a username as literal data, returning a row or None."""
    return connection.execute(build_query(username)).fetchone()
''',
    "query_builder.py": '''def build_query(username):
    """Build a database lookup consumed by app.find_user."""
    return f"SELECT name FROM users WHERE name = '{username}'"
''',
    "test_app.py": SQL_TESTS,
}, {
    "query_builder.py": '''def build_query(username):
    """Build a parameterized database lookup consumed by app.find_user."""
    return "SELECT name FROM users WHERE name = ?"
''',
    "app.py": '''from query_builder import build_query

def find_user(connection, username):
    """Look up a username as literal data, returning a row or None."""
    return connection.execute(build_query(username), (username,)).fetchone()
''',
})

DEPENDENCY = AcceptanceCase("httpx_dependency", {
    "app.py": '''import httpx

def build_request(raw_payload):
    """Build, but never send, a request from a Python literal payload."""
    payload = eval(raw_payload)
    return httpx.Request("POST", "https://example.test/submit", json=payload)
''',
    "test_app.py": '''import json
import unittest
from app import build_request

class TestRequest(unittest.TestCase):
    def test_dictionary(self):
        request = build_request("{'count': 3}")
        self.assertEqual(request.method, "POST")
        self.assertEqual(json.loads(request.content), {"count": 3})

    def test_list(self):
        self.assertEqual(json.loads(build_request("[1, 2]").content), [1, 2])
''',
    "requirements.txt": "httpx==0.28.1\n",
}, {"app.py": '''import ast
import httpx

def build_request(raw_payload):
    """Build, but never send, a request from a Python literal payload."""
    payload = ast.literal_eval(raw_payload)
    return httpx.Request("POST", "https://example.test/submit", json=payload)
'''})

CASES = {case.name: case for case in (COMMAND, SQL, MULTIFILE, DEPENDENCY)}
