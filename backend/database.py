"""Local PostgreSQL configuration and request-scoped database sessions."""

from functools import lru_cache
import os
from pathlib import Path

from dotenv import dotenv_values
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import Session


class DatabaseConfigurationError(RuntimeError):
    """Required local database settings are missing or invalid."""


def database_url(*, testing=False):
    settings = dotenv_values(Path(__file__).resolve().parents[1] / ".env", interpolate=False)

    def value(name, default=None):
        key = f"SENTINELAI_DB_{name}"
        return os.environ.get(key, settings.get(key, default))

    host = value("HOST", "127.0.0.1")
    password = value("PASSWORD")
    username = value("USER", "sentinelai_user")
    development_db = value("NAME", "sentinelai_dev")
    database = value("TEST_NAME", "sentinelai_test") if testing else development_db
    if host not in {"127.0.0.1", "::1", "localhost"} or not (username and password and database):
        raise DatabaseConfigurationError("A local PostgreSQL host, role, database and password are required")
    if testing and database == development_db:
        raise DatabaseConfigurationError("Use a dedicated test database different from development")
    try:
        port = int(value("PORT", "5432"))
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise DatabaseConfigurationError("Configure a valid PostgreSQL port") from error
    return URL.create("postgresql+psycopg", username, password, host, port, database)


@lru_cache(maxsize=1)
def get_engine():
    return create_engine(database_url(), pool_pre_ping=True, hide_parameters=True)


def get_session():
    with Session(get_engine(), expire_on_commit=False) as session:
        yield session
