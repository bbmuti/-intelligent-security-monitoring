"""Harden refresh sessions and make collector ingestion idempotent."""

import sqlalchemy as sa
from alembic import op

revision = "20260820_0002"
down_revision = "20260820_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analyst_users") as batch:
        batch.add_column(
            sa.Column("password_iterations", sa.Integer(), nullable=False, server_default="210000")
        )
    with op.batch_alter_table("analyst_users") as batch:
        batch.alter_column(
            "password_iterations",
            existing_type=sa.Integer(),
            nullable=False,
            server_default=None,
        )

    with op.batch_alter_table("refresh_sessions") as batch:
        batch.add_column(sa.Column("family_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("parent_jti", sa.String(64), nullable=True))
    op.execute(sa.text("UPDATE refresh_sessions SET family_id = jti WHERE family_id IS NULL"))
    with op.batch_alter_table("refresh_sessions") as batch:
        batch.alter_column("family_id", existing_type=sa.String(64), nullable=False)
        batch.create_index("ix_refresh_sessions_family_id", ["family_id"])

    with op.batch_alter_table("security_events") as batch:
        batch.add_column(sa.Column("source_event_id", sa.String(255), nullable=True))
        batch.create_unique_constraint(
            "uq_security_events_source_event_id", ["source", "source_event_id"]
        )
        batch.create_index("ix_security_events_ip_timestamp", ["ip_address", "timestamp"])
        batch.create_index("ix_security_events_user_timestamp", ["user_id", "timestamp"])


def downgrade() -> None:
    with op.batch_alter_table("security_events") as batch:
        batch.drop_index("ix_security_events_user_timestamp")
        batch.drop_index("ix_security_events_ip_timestamp")
        batch.drop_constraint("uq_security_events_source_event_id", type_="unique")
        batch.drop_column("source_event_id")

    with op.batch_alter_table("refresh_sessions") as batch:
        batch.drop_index("ix_refresh_sessions_family_id")
        batch.drop_column("parent_jti")
        batch.drop_column("family_id")

    with op.batch_alter_table("analyst_users") as batch:
        batch.drop_column("password_iterations")
