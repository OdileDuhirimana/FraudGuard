from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# Make the `app` package importable regardless of the working directory
# alembic is invoked from (prepend_sys_path = . in alembic.ini already
# covers the common case of running from backend/, this is a defensive
# fallback for CI environments that may invoke alembic differently).
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, SQLALCHEMY_DATABASE_URL  # noqa: E402
from app import models  # noqa: E402,F401  (import registers all tables on Base.metadata)

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Autogenerate support: point Alembic at the app's actual SQLAlchemy
# metadata instead of hand-maintaining migrations independently of the
# ORM models — this is what lets `alembic revision --autogenerate` detect
# model changes.
target_metadata = Base.metadata

# The database URL is sourced from the same Settings object the app uses
# (backend/app/config.py) rather than a hardcoded alembic.ini value, so
# migrations always run against whatever DATABASE_URL/FG_DB_URL the
# environment actually specifies.
#
# BUG FIX (found during functional verification): this previously ran
# unconditionally, clobbering any URL the caller had already set on `config`
# before invoking Alembic's `command.upgrade`/`command.downgrade`. That
# silently broke tests/test_migrations.py, which explicitly points a fresh
# `Config` at an isolated, throwaway temp-file SQLite database specifically
# so its `alembic downgrade base` step (which drops every table) can never
# touch a real database — the override here defeated that isolation and
# made the test drop every table in the *live app's* configured database
# instead (by default `sqlite:///./fraudguard.db`, the same file the dev
# server and `scripts/seed.py` use), reproducibly wiping real local/demo
# data on every test run. alembic.ini ships a non-functional placeholder
# URL (`driver://user:pass@localhost/dbname`) precisely because it's never
# meant to be used as-is; only fall back to the app's configured URL when
# the caller hasn't already replaced that placeholder with a real one, so
# CLI usage (`alembic upgrade head`) still defaults to the app's database
# while a caller that explicitly sets its own URL (tests, `alembic -x`)
# is respected instead of overridden.
_ALEMBIC_INI_PLACEHOLDER_URL = "driver://user:pass@localhost/dbname"
if config.get_main_option("sqlalchemy.url") in (None, _ALEMBIC_INI_PLACEHOLDER_URL):
    config.set_main_option("sqlalchemy.url", SQLALCHEMY_DATABASE_URL)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
