"""Unit tests for AutoPatch AuditService and secret sanitization."""

import json
from datetime import datetime, timezone
import pytest
from sqlalchemy.orm import Session

from backend.database.models import AuditEventModel, utc_now
from backend.models.audit import AuditEventStatus, AuditEventType
from backend.services.audit import AuditService, sanitize_metadata


class TestMetadataSanitization:
    """Test suite for secret sanitization and recursive redaction."""

    def test_redacts_api_keys_and_passwords(self):
        """Verify sensitive credentials are replaced with [REDACTED]."""
        raw_metadata = {
            "api_key": "sk-1234567890abcdef",
            "password": "SuperSecretPassword123!",
            "authorization": "Bearer my-secret-jwt-token",
            "safe_metric": 42,
            "filename": "app.py",
        }
        sanitized = sanitize_metadata(raw_metadata)

        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["authorization"] == "[REDACTED]"
        assert sanitized["safe_metric"] == 42
        assert sanitized["filename"] == "app.py"

    def test_recursive_nested_redaction(self):
        """Verify redaction propagates through nested dictionaries and lists."""
        nested = {
            "service_config": {
                "llm": {
                    "provider": "openai",
                    "OPENAI_API_KEY": "sk-proj-secret123",
                    "timeout": 30,
                },
                "tokens": ["normal_token_item", {"secret_token": "hidden_val"}],
            },
            "credentials": [
                {"cookie": "session=abc123xyz"},
                {"private_key": "-----BEGIN RSA PRIVATE KEY-----"},
                {"passwd": "admin"},
            ]
        }
        sanitized = sanitize_metadata(nested)

        assert sanitized["service_config"]["llm"]["OPENAI_API_KEY"] == "[REDACTED]"
        assert sanitized["service_config"]["llm"]["provider"] == "openai"
        assert sanitized["service_config"]["llm"]["timeout"] == 30
        assert sanitized["service_config"]["tokens"][1]["secret_token"] == "[REDACTED]"
        assert sanitized["credentials"][0]["cookie"] == "[REDACTED]"
        assert sanitized["credentials"][1]["private_key"] == "[REDACTED]"
        assert sanitized["credentials"][2]["passwd"] == "[REDACTED]"

    def test_input_immutability(self):
        """Verify input dictionary is not modified in-place."""
        original = {"api_key": "top-secret-val", "normal": "val"}
        original_copy = dict(original)
        _ = sanitize_metadata(original)
        assert original == original_copy


class TestAuditServiceUnit:
    """Unit test suite for AuditService persistence, nullable foreign keys, and queries."""

    def test_record_event_creation(self, db_session: Session):
        """Test creating and retrieving an audit event."""
        service = AuditService()
        event = service.record_event(
            event_type=AuditEventType.SCAN_STARTED,
            workflow_id="wf-test-001",
            vulnerability_id=None,
            patch_attempt_id=None,
            validation_id=None,
            event_status=AuditEventStatus.INFO,
            message="Test scan started",
            metadata={"repo": "/tmp/repo", "scanner_count": 2},
            session=db_session,
        )

        assert event.id.startswith("AUDIT-")
        assert event.workflow_id == "wf-test-001"
        assert event.event_type == AuditEventType.SCAN_STARTED.value
        assert event.event_status == AuditEventStatus.INFO.value
        assert event.message == "Test scan started"
        assert event.created_at is not None

        meta = event.get_metadata()
        assert meta["repo"] == "/tmp/repo"
        assert meta["scanner_count"] == 2

    def test_metadata_serialization(self, db_session: Session):
        """Verify structured JSON metadata round-trips cleanly."""
        service = AuditService()
        metadata_payload = {
            "scanner_status": "COMPLETED",
            "finding_count": 3,
            "duration": 1.25,
            "files": ["app.py", "database.py"],
        }
        event = service.record_event(
            event_type=AuditEventType.SCAN_COMPLETED,
            workflow_id="wf-test-002",
            metadata=metadata_payload,
            session=db_session,
        )

        fetched = service.get_event(event.id, session=db_session)
        assert fetched is not None
        assert fetched.get_metadata() == metadata_payload

    def test_secret_redaction_in_database(self, db_session: Session):
        """Security requirement: verify secrets are permanently redacted in database metadata."""
        service = AuditService()
        event = service.record_event(
            event_type=AuditEventType.PATCH_GENERATION_STARTED,
            workflow_id="wf-test-003",
            metadata={
                "api_key": "secret-value",
                "password": "hunter2",
                "authorization": "Bearer secret",
                "model": "gpt-4o",
            },
            session=db_session,
        )

        fetched = service.get_event(event.id, session=db_session)
        meta = fetched.get_metadata()

        assert meta["api_key"] == "[REDACTED]"
        assert meta["password"] == "[REDACTED]"
        assert meta["authorization"] == "[REDACTED]"
        assert meta["model"] == "gpt-4o"
        assert "secret-value" not in fetched.metadata_json
        assert "hunter2" not in fetched.metadata_json

    def test_nullable_foreign_keys(self, db_session: Session):
        """Verify events do not require every foreign key ID to be non-null."""
        service = AuditService()

        # 1. Only workflow_id
        e1 = service.record_event(
            event_type=AuditEventType.WORKFLOW_CREATED,
            workflow_id="wf-null-test",
            session=db_session,
        )
        assert e1.workflow_id == "wf-null-test"
        assert e1.vulnerability_id is None
        assert e1.patch_attempt_id is None
        assert e1.validation_id is None

        # 2. Only vulnerability_id
        e2 = service.record_event(
            event_type=AuditEventType.CONTEXT_CREATED,
            vulnerability_id="VULN-001",
            session=db_session,
        )
        assert e2.workflow_id is None
        assert e2.vulnerability_id == "VULN-001"

        # 3. Only patch_attempt_id and validation_id
        e3 = service.record_event(
            event_type=AuditEventType.PATCH_VALIDATED,
            patch_attempt_id="PATCH-001",
            validation_id="VAL-001",
            session=db_session,
        )
        assert e3.patch_attempt_id == "PATCH-001"
        assert e3.validation_id == "VAL-001"

    def test_event_type_validation(self, db_session: Session):
        """Verify all enum types can be persisted and string conversions succeed."""
        service = AuditService()
        for ev_type in AuditEventType:
            event = service.record_event(
                event_type=ev_type,
                message=f"Testing {ev_type.value}",
                session=db_session,
            )
            assert event.event_type == ev_type.value

    def test_timestamp_creation(self, db_session: Session):
        """Verify timestamps are automatically populated as UTC datetimes."""
        service = AuditService()
        before = utc_now()
        event = service.record_event(
            event_type=AuditEventType.SYSTEM_ERROR,
            message="System ping",
            session=db_session,
        )
        after = utc_now()

        assert before <= event.created_at <= after
