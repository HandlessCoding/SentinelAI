"""Add continuous Zeek sources and atomic processing checkpoints."""

import sqlalchemy as sa
from alembic import op

revision = "0003_zeek_streams"
down_revision = "0002_zeek_traffic"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint("ck_zeek_captures_flow_count", "zeek_captures", type_="check")
    op.drop_constraint("ck_zeek_captures_source", "zeek_captures", type_="check")
    op.alter_column("zeek_captures", "pcap_sha256", nullable=True)
    op.alter_column("zeek_captures", "conn_sha256", nullable=True)
    op.alter_column("zeek_captures", "flow_count", type_=sa.BigInteger())
    op.create_check_constraint(
        "ck_zeek_captures_provenance", "zeek_captures",
        "(source IN ('authorized_lab', 'authorized_archive') AND flow_count BETWEEN 1 AND 10000 "
        "AND pcap_sha256 IS NOT NULL AND conn_sha256 IS NOT NULL) OR "
        "(source IN ('recorded_replay', 'connected_sensor') AND flow_count >= 0 "
        "AND pcap_sha256 IS NULL AND conn_sha256 IS NULL)",
    )
    op.alter_column("zeek_flows", "source_row", type_=sa.BigInteger())
    op.add_column("zeek_flows", sa.Column("stream_key", sa.String(64)))
    op.add_column("zeek_flows", sa.Column("source_file", sa.String(64)))
    op.add_column("zeek_flows", sa.Column("source_offset", sa.BigInteger()))
    op.add_column("zeek_flows", sa.Column("ingested_at", sa.DateTime(timezone=True)))
    op.create_unique_constraint("uq_zeek_flows_stream_key", "zeek_flows", ["capture_id", "stream_key"])
    op.create_index("ix_zeek_flows_ingested", "zeek_flows", ["ingested_at", "id"])
    op.create_table(
        "zeek_streams",
        sa.Column("capture_id", sa.String(64), sa.ForeignKey("zeek_captures.capture_id"), primary_key=True),
        sa.Column("replay_capture_id", sa.String(64)),
        sa.Column("replay_conn_sha256", sa.String(64)),
        sa.Column("file_identity", sa.String(64)),
        sa.Column("byte_offset", sa.BigInteger(), nullable=False),
        sa.Column("anchor", sa.String(64)),
        sa.Column("discarding", sa.Boolean(), nullable=False),
        sa.Column("rows_seen", sa.BigInteger(), nullable=False),
        sa.Column("rejected_rows", sa.BigInteger(), nullable=False),
        sa.Column("duplicate_rows", sa.BigInteger(), nullable=False),
        sa.Column("backlog_bytes", sa.BigInteger()),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("last_error", sa.String(48)),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_ingested_at", sa.DateTime(timezone=True)),
    )


def downgrade():
    # Revision 0002 cannot represent stream traffic. Offline captures survive.
    op.drop_table("zeek_streams")
    op.execute("DELETE FROM zeek_flows WHERE capture_id IN "
               "(SELECT capture_id FROM zeek_captures WHERE source IN ('recorded_replay', 'connected_sensor'))")
    op.execute("DELETE FROM zeek_captures WHERE source IN ('recorded_replay', 'connected_sensor')")
    op.drop_index("ix_zeek_flows_ingested", table_name="zeek_flows")
    op.drop_constraint("uq_zeek_flows_stream_key", "zeek_flows", type_="unique")
    for name in ("ingested_at", "source_offset", "source_file", "stream_key"):
        op.drop_column("zeek_flows", name)
    op.alter_column("zeek_flows", "source_row", type_=sa.Integer())
    op.drop_constraint("ck_zeek_captures_provenance", "zeek_captures", type_="check")
    op.alter_column("zeek_captures", "pcap_sha256", nullable=False)
    op.alter_column("zeek_captures", "conn_sha256", nullable=False)
    op.alter_column("zeek_captures", "flow_count", type_=sa.Integer())
    op.create_check_constraint("ck_zeek_captures_flow_count", "zeek_captures", "flow_count BETWEEN 1 AND 10000")
    op.create_check_constraint("ck_zeek_captures_source", "zeek_captures",
                               "source IN ('authorized_lab', 'authorized_archive')")
