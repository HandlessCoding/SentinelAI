"""Local PostgreSQL configuration and request-scoped database sessions."""

import os
import socket
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

from dotenv import dotenv_values
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import Session


class DatabaseConfigurationError(RuntimeError):
    """Required local database settings are missing or invalid."""


def _loopback_addresses(host: str) -> list[str]:
    if host != "localhost":
        return [host]
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        addresses: dict[str, None] = {}
        for _, _, _, _, sockaddr in answers:
            address = sockaddr[0]
            if not isinstance(address, str) or not ip_address(address).is_loopback:
                break
            addresses[address] = None
        else:
            if addresses:
                return list(addresses)
    except (OSError, ValueError):
        pass
    raise DatabaseConfigurationError("PostgreSQL localhost must resolve exclusively to loopback addresses")


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
        port_setting = value("PORT", "5432")
        if port_setting is None:
            raise ValueError
        port = int(port_setting)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError as error:
        raise DatabaseConfigurationError("Configure a valid PostgreSQL port") from error
    addresses = _loopback_addresses(host)
    # An explicit numeric address prevents libpq environment/service defaults
    # from redirecting the connection or causing a second hostname resolution.
    return URL.create(
        "postgresql+psycopg",
        username,
        password,
        ",".join([host] * len(addresses)),
        port,
        database,
        query={"hostaddr": ",".join(addresses)},
    )


@lru_cache(maxsize=1)
def get_engine():
    return create_engine(
        database_url(),
        connect_args={"connect_timeout": 3},
        pool_timeout=5,
        pool_pre_ping=True,
        hide_parameters=True,
    )


def get_session():
    with Session(get_engine(), expire_on_commit=False) as session:
        yield session
