import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context

from dotenv import load_dotenv

# Load env variables from .env
load_dotenv()

# Alembic Config object, provides access to values in alembic.ini
config = context.config

# Set DB URL from environment variable
database_url = os.environ.get("DATABASE_URL")
if database_url:
    config.set_main_option('sqlalchemy.url', database_url)

# Interpret the config file for Python logging.
fileConfig(config.config_file_name)

# Import models' Base
from src.db.models import Base

target_metadata = Base.metadata

def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
