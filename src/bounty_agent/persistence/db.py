"""SQLite engine factory."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from bounty_agent.persistence.models import Base


def _enable_sqlite_foreign_keys(
    dbapi_connection: object,
    _connection_record: object,
) -> None:
    """SQLite requires PRAGMA foreign_keys=ON to enforce cascade rules."""
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def make_engine(sqlite_path: Path | str) -> Engine:
    """Create an SQLite engine and ensure the schema is in place."""
    url = _sqlite_url(sqlite_path)
    engine = create_engine(url, future=True)
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    Base.metadata.create_all(engine)
    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a session factory bound to the given engine."""
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _sqlite_url(path: Path | str) -> str:
    if str(path) == ":memory:":
        return "sqlite:///:memory:"
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{p}"


__all__ = ["make_engine", "make_session_factory"]
