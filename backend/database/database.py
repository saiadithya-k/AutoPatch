"""SQLAlchemy database connection and session management."""

from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from backend.config import get_settings

settings = get_settings()

# For SQLite, enable check_same_thread=False for multi-threaded FastAPI workers
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db() -> None:
    """Initialize database tables and apply backward-compatible column migrations if needed."""
    from backend.database import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    apply_mvp_migrations(engine)

    # Lightweight backward-compatible column migration for SQLite
    if settings.DATABASE_URL.startswith("sqlite"):
        from sqlalchemy import text
        with engine.connect() as conn:
            # 1. Patch attempts columns
            try:
                res = conn.execute(text("PRAGMA table_info(patch_attempts)")).fetchall()
                existing_cols = {row[1] for row in res}
                if existing_cols:
                    if "parent_patch_id" not in existing_cols:
                        conn.execute(text("ALTER TABLE patch_attempts ADD COLUMN parent_patch_id VARCHAR"))
                    if "retry_reason" not in existing_cols:
                        conn.execute(text("ALTER TABLE patch_attempts ADD COLUMN retry_reason TEXT"))
                    if "validation_id" not in existing_cols:
                        conn.execute(text("ALTER TABLE patch_attempts ADD COLUMN validation_id VARCHAR"))
                    if "retryable" not in existing_cols:
                        conn.execute(text("ALTER TABLE patch_attempts ADD COLUMN retryable BOOLEAN DEFAULT 1"))
                    if "failure_category" not in existing_cols:
                        conn.execute(text("ALTER TABLE patch_attempts ADD COLUMN failure_category VARCHAR"))
                    if "retry_decision" not in existing_cols:
                        conn.execute(text("ALTER TABLE patch_attempts ADD COLUMN retry_decision TEXT"))
                    conn.commit()
            except Exception:
                pass

            # 2. Validation results columns
            try:
                res = conn.execute(text("PRAGMA table_info(validation_results)")).fetchall()
                existing_val_cols = {row[1] for row in res}
                if existing_val_cols:
                    if "syntax_check_passed" not in existing_val_cols:
                        conn.execute(text("ALTER TABLE validation_results ADD COLUMN syntax_check_passed BOOLEAN DEFAULT 0"))
                    if "new_findings_count" not in existing_val_cols:
                        conn.execute(text("ALTER TABLE validation_results ADD COLUMN new_findings_count INTEGER DEFAULT 0"))
                    if "new_findings" not in existing_val_cols:
                        conn.execute(text("ALTER TABLE validation_results ADD COLUMN new_findings TEXT"))
                    if "duration" not in existing_val_cols:
                        conn.execute(text("ALTER TABLE validation_results ADD COLUMN duration FLOAT DEFAULT 0.0"))
                    if "failure_category" not in existing_val_cols:
                        conn.execute(text("ALTER TABLE validation_results ADD COLUMN failure_category VARCHAR"))
                    conn.commit()
            except Exception:
                pass

            # 3. Audit events table verification
            try:
                res = conn.execute(text("PRAGMA table_info(audit_events)")).fetchall()
                existing_audit_cols = {row[1] for row in res}
                if not existing_audit_cols and "audit_events" in Base.metadata.tables:
                    Base.metadata.tables["audit_events"].create(bind=engine, checkfirst=True)
            except Exception:
                pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def apply_mvp_migrations(target_engine) -> None:
    """Idempotent additive SQLite migration; failures stop startup visibly."""
    if target_engine.dialect.name != "sqlite":
        return
    from sqlalchemy import inspect, text
    additions = {
        "workflows": {
            "processed_findings": "INTEGER NOT NULL DEFAULT 0",
            "total_findings": "INTEGER NOT NULL DEFAULT 0",
            "reviewable_count": "INTEGER NOT NULL DEFAULT 0",
            "failed_count": "INTEGER NOT NULL DEFAULT 0",
            "outcome": "VARCHAR", "errors_json": "TEXT", "request_json": "TEXT", "scan_metadata": "TEXT",
        },
        "validation_results": {"scanner_metadata": "TEXT"},
    }
    with target_engine.begin() as connection:
        inspector = inspect(connection)
        for table, columns in additions.items():
            if not inspector.has_table(table):
                continue
            present = {column["name"] for column in inspector.get_columns(table)}
            for name, definition in columns.items():
                if name not in present:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
