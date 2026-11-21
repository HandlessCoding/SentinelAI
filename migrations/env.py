"""Run Alembic with the same local PostgreSQL settings as the API."""

from alembic import context
from sqlalchemy import create_engine

from backend.database import database_url
from backend.models import Base


def migrate(connection=None):
    settings = {"connection": connection} if connection is not None else {
        "dialect_name": "postgresql", "literal_binds": True,
    }
    context.configure(**settings, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    migrate()
elif (connection := context.config.attributes.get("connection")) is not None:
    migrate(connection)
else:
    engine = create_engine(database_url(), hide_parameters=True)
    try:
        with engine.connect() as connection:
            migrate(connection)
    finally:
        engine.dispose()
