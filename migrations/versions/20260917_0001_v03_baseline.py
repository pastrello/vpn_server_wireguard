"""VPNHub v0.3 schema baseline

Revision ID: 20260917_0001
Revises: None
"""
from alembic import op
import sqlalchemy as sa

revision = "20260917_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "sites",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("vpn_cidr", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("vpn_cidr"),
    )
    op.create_index("ix_sites_name", "sites", ["name"])

    op.create_table(
        "networks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("translated_cidr", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_networks_site_id", "networks", ["site_id"])
    op.create_index("ix_networks_cidr", "networks", ["cidr"])

    op.create_table(
        "peers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("peer_type", sa.String(length=20), nullable=False),
        sa.Column("public_key", sa.String(length=128), nullable=False),
        sa.Column("preshared_key_enc", sa.Text(), nullable=True),
        sa.Column("assigned_ip", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("latest_handshake", sa.DateTime(), nullable=True),
        sa.Column("endpoint", sa.String(length=255), nullable=True),
        sa.Column("rx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("tx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("public_key"),
        sa.UniqueConstraint("assigned_ip"),
    )
    op.create_index("ix_peers_site_id", "peers", ["site_id"])
    op.create_index("ix_peers_public_key", "peers", ["public_key"])
    op.create_index("ix_peers_assigned_ip", "peers", ["assigned_ip"])

    op.create_table(
        "admin_peers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("public_key", sa.String(length=128), nullable=False),
        sa.Column("preshared_key_enc", sa.Text(), nullable=True),
        sa.Column("assigned_ip", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("latest_handshake", sa.DateTime(), nullable=True),
        sa.Column("endpoint", sa.String(length=255), nullable=True),
        sa.Column("rx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("tx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("public_key"),
        sa.UniqueConstraint("assigned_ip"),
    )
    op.create_index("ix_admin_peers_public_key", "admin_peers", ["public_key"])
    op.create_index("ix_admin_peers_assigned_ip", "admin_peers", ["assigned_ip"])


def downgrade():
    op.drop_table("admin_peers")
    op.drop_table("peers")
    op.drop_table("networks")
    op.drop_table("sites")
    op.drop_table("users")
