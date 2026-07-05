"""add otp expiry

Revision ID: ba66accbbf9e
Revises: 26d5cbd4b026
Create Date: 2026-07-04 18:48:50.232162

Adds OTPChallenge.expires_at (see models.OTP_TTL_MINUTES / models.py
_default_otp_expiry). Backfills any pre-existing rows to CURRENT_TIMESTAMP
rather than leaving them nullable or backdating a plausible original
expiry — for a security-relevant expiry column, "treat historical rows as
already expired, forcing a fresh OTP request" is the fail-closed choice: it
never leaves a pre-migration challenge validity in an ambiguous state.
Using batch_alter_table for SQLite compatibility (SQLite cannot ALTER a
column's NOT NULL/default in place).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ba66accbbf9e'
down_revision: Union[str, Sequence[str], None] = '26d5cbd4b026'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("otp_challenges") as batch_op:
        batch_op.add_column(
            sa.Column(
                "expires_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            )
        )
    # Drop the server default once existing rows are backfilled so future
    # inserts rely solely on the ORM-level default (OTP_TTL_MINUTES from
    # creation time), not a DB-level "now" that would omit the TTL offset.
    with op.batch_alter_table("otp_challenges") as batch_op:
        batch_op.alter_column("expires_at", server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("otp_challenges") as batch_op:
        batch_op.drop_column("expires_at")
