"""
Proves the Alembic migration chain actually runs upgrade -> downgrade ->
upgrade cleanly against a throwaway SQLite database. This is what catches a
migration that "looks right" in the generated file but fails to apply
(mismatched constraint names, unsupported ALTER on SQLite, etc.).

Deliberately does NOT reuse the `client`/`db_engine` fixtures from
conftest.py, since those create schema directly via SQLAlchemy metadata
(fast path for the rest of the suite) — this test exists specifically to
exercise the Alembic code path those fixtures bypass.
"""
import uuid

from alembic import command
from alembic.config import Config


def _alembic_config(db_path) -> Config:
    backend_dir = __file__.rsplit("/tests/", 1)[0]
    cfg = Config(f"{backend_dir}/alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def test_upgrade_head_then_downgrade_base_then_upgrade_again(tmp_path):
    db_path = tmp_path / f"migration_test_{uuid.uuid4().hex}.db"
    cfg = _alembic_config(db_path)

    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")  # must still be re-runnable after a full downgrade
