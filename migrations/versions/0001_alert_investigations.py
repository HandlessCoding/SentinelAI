"""Create prediction batches, suspected-attack alerts, incidents and notes."""

import sqlalchemy as sa
from alembic import op

revision = "0001_alert_investigations"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "prediction_batches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("model_version", sa.String(80), nullable=False),
        sa.Column("decision_threshold", sa.Double(), nullable=False),
        sa.Column("prediction_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("idempotency_key", name="uq_prediction_batches_idempotency_key"),
        sa.CheckConstraint("record_count BETWEEN 1 AND 100", name="ck_prediction_batches_record_count"),
        sa.CheckConstraint("decision_threshold BETWEEN 0 AND 1", name="ck_prediction_batches_threshold"),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('open', 'investigating', 'resolved')", name="ck_incidents_status"),
    )
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("batch_id", sa.Uuid(), sa.ForeignKey("prediction_batches.id"), nullable=False),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id"), nullable=True),
        sa.Column("record_index", sa.Integer(), nullable=False),
        sa.Column("attack_probability", sa.Double(), nullable=False),
        sa.UniqueConstraint("batch_id", "record_index", name="uq_alerts_batch_record"),
        sa.CheckConstraint("record_index BETWEEN 0 AND 99", name="ck_alerts_record_index"),
        sa.CheckConstraint("attack_probability BETWEEN 0 AND 1", name="ck_alerts_attack_probability"),
    )
    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])
    op.create_table(
        "analyst_notes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("author", sa.String(80), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_analyst_notes_incident_id", "analyst_notes", ["incident_id"])


def downgrade():
    op.drop_table("analyst_notes")
    op.drop_table("alerts")
    op.drop_table("incidents")
    op.drop_table("prediction_batches")
