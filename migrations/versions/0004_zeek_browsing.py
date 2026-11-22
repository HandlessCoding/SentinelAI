"""Record acknowledged Zeek rotations and support stable flow browsing."""

from alembic import op
import sqlalchemy as sa


revision = "0004_zeek_browsing"
down_revision = "0003_zeek_streams"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("zeek_streams", sa.Column("last_drained_file", sa.String(64)))
    op.add_column("zeek_flows", sa.Column("insert_xid", sa.Text(), nullable=False,
                                         server_default=sa.text("pg_current_xact_id()::text")))


def downgrade():
    op.drop_column("zeek_flows", "insert_xid")
    op.drop_column("zeek_streams", "last_drained_file")
