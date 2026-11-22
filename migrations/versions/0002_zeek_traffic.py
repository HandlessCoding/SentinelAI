"""Add offline Zeek capture provenance and connection records."""

import sqlalchemy as sa
from alembic import op

revision = "0002_zeek_traffic"
down_revision = "0001_alert_investigations"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "zeek_captures",
        sa.Column("capture_id", sa.String(64), primary_key=True),
        sa.Column("session_id", sa.String(64), nullable=False),
        sa.Column("environment_id", sa.String(64), nullable=False),
        sa.Column("observation_point", sa.String(64), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("zeek_version", sa.String(128), nullable=False),
        sa.Column("pcap_sha256", sa.String(64), nullable=False),
        sa.Column("conn_sha256", sa.String(64), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("pcap_sha256", name="uq_zeek_captures_pcap_sha256"),
        sa.UniqueConstraint("conn_sha256", name="uq_zeek_captures_conn_sha256"),
        sa.CheckConstraint("flow_count BETWEEN 1 AND 10000", name="ck_zeek_captures_flow_count"),
        sa.CheckConstraint("source IN ('authorized_lab', 'authorized_archive')", name="ck_zeek_captures_source"),
    )
    op.create_table(
        "zeek_flows",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("capture_id", sa.String(64), sa.ForeignKey("zeek_captures.capture_id"), nullable=False),
        sa.Column("source_row", sa.Integer(), nullable=False),
        sa.Column("timestamp_ns", sa.BigInteger(), nullable=False),
        sa.Column("proto", sa.String(24), nullable=False),
        sa.Column("conn_state", sa.String(24)),
        sa.Column("service", sa.String(1024)),
        sa.Column("history", sa.String(1024)),
        sa.Column("orig_host", sa.String(45)),
        sa.Column("resp_host", sa.String(45)),
        sa.Column("orig_port", sa.Integer()),
        sa.Column("resp_port", sa.Integer()),
        *(sa.Column(name, sa.BigInteger()) for name in (
            "duration_ns", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
            "orig_bytes", "resp_bytes", "missed_bytes",
        )),
        sa.Column("ground_truth", sa.String(8), nullable=False),
        sa.Column("label_category", sa.String(64)),
        sa.Column("label_reason", sa.String(40), nullable=False),
        sa.Column("rule_code", sa.String(32)),
        sa.UniqueConstraint("capture_id", "source_row", name="uq_zeek_flows_source_row"),
        sa.CheckConstraint("source_row > 0 AND timestamp_ns >= 0", name="ck_zeek_flows_provenance"),
        sa.CheckConstraint("ground_truth IN ('benign', 'attack', 'unknown')", name="ck_zeek_flows_ground_truth"),
    )
    op.create_index("ix_zeek_flows_order", "zeek_flows", ["timestamp_ns", "id"])


def downgrade():
    op.drop_table("zeek_flows")
    op.drop_table("zeek_captures")
