"""Prepare VPNInstance abstraction

Revision ID: 20260918_0003
Revises: 20260917_0002
"""
from alembic import op
import sqlalchemy as sa

revision = "20260918_0003"
down_revision = "20260917_0002"
branch_labels = None
depends_on = None


def _drop_legacy_unique(table, constraint_name, index_name):
    """Drop unique object whether legacy DB has constraint or unique index."""
    bind = op.get_bind()

    constraint_exists = bind.execute(
        sa.text("""
            SELECT 1
              FROM pg_constraint
             WHERE conrelid = to_regclass(:table_name)
               AND conname = :constraint_name
               AND contype = 'u'
        """),
        {
            "table_name": f"public.{table}",
            "constraint_name": constraint_name,
        },
    ).scalar()

    if constraint_exists:
        op.drop_constraint(
            constraint_name,
            table,
            type_="unique",
        )
        return

    index_unique = bind.execute(
        sa.text("""
            SELECT i.indisunique
              FROM pg_class t
              JOIN pg_namespace n
                ON n.oid = t.relnamespace
              JOIN pg_index i
                ON i.indrelid = t.oid
              JOIN pg_class x
                ON x.oid = i.indexrelid
             WHERE n.nspname = 'public'
               AND t.relname = :table_name
               AND x.relname = :index_name
        """),
        {
            "table_name": table,
            "index_name": index_name,
        },
    ).scalar()

    if index_unique:
        op.drop_index(
            index_name,
            table_name=table,
        )


def upgrade():
    op.create_table(
        "vpn_instances",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("interface_name", sa.String(length=32), nullable=False),
        sa.Column("endpoint", sa.String(length=255), nullable=False),
        sa.Column("listen_port", sa.Integer(), nullable=False),
        sa.Column("vpn_pool", sa.String(length=64), nullable=False),
        sa.Column("server_address", sa.String(length=64), nullable=False),
        sa.Column("server_public_key", sa.String(length=128), nullable=False),
        sa.Column("private_key_path", sa.String(length=255), nullable=False),
        sa.Column("route_protocol", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("interface_name"),
        sa.UniqueConstraint("listen_port"),
    )
    op.create_index(
        "uq_default_vpn_instance",
        "vpn_instances",
        ["is_default"],
        unique=True,
        postgresql_where=sa.text("is_default = true"),
    )

    op.execute(sa.text("""
        INSERT INTO vpn_instances (
            id, name, interface_name, endpoint, listen_port,
            vpn_pool, server_address, server_public_key,
            private_key_path, route_protocol, enabled,
            is_default, created_at
        )
        VALUES (
            1, 'Principal', 'wg0', 'vpn.example.com:51820', 51820,
            '10.250.0.0/16', '10.250.0.1/16', 'CHANGE_ME',
            '/etc/wireguard/vpnhub-server.key', 186, true,
            true, CURRENT_TIMESTAMP
        )
    """))

    op.add_column(
        "sites",
        sa.Column("vpn_instance_id", sa.Integer(), nullable=True),
    )
    op.execute("UPDATE sites SET vpn_instance_id = 1")
    op.alter_column(
        "sites",
        "vpn_instance_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
    op.create_foreign_key(
        "fk_sites_vpn_instance",
        "sites",
        "vpn_instances",
        ["vpn_instance_id"],
        ["id"],
    )
    op.create_index(
        "ix_sites_vpn_instance_id",
        "sites",
        ["vpn_instance_id"],
    )

    # Global uniqueness from the single-wg model becomes per Instance.
    _drop_legacy_unique(
        "sites",
        "sites_name_key",
        "ix_sites_name",
    )
    _drop_legacy_unique(
        "sites",
        "sites_vpn_cidr_key",
        "ix_sites_vpn_cidr",
    )
    op.create_unique_constraint(
        "uq_site_name_per_instance",
        "sites",
        ["vpn_instance_id", "name"],
    )
    op.create_unique_constraint(
        "uq_site_cidr_per_instance",
        "sites",
        ["vpn_instance_id", "vpn_cidr"],
    )

    op.add_column(
        "admin_peers",
        sa.Column("vpn_instance_id", sa.Integer(), nullable=True),
    )
    op.execute("UPDATE admin_peers SET vpn_instance_id = 1")
    op.alter_column(
        "admin_peers",
        "vpn_instance_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
    op.create_foreign_key(
        "fk_admin_peers_vpn_instance",
        "admin_peers",
        "vpn_instances",
        ["vpn_instance_id"],
        ["id"],
    )
    op.create_index(
        "ix_admin_peers_vpn_instance_id",
        "admin_peers",
        ["vpn_instance_id"],
    )

    _drop_legacy_unique(
        "admin_peers",
        "admin_peers_assigned_ip_key",
        "ix_admin_peers_assigned_ip",
    )
    op.create_unique_constraint(
        "uq_admin_peer_ip_per_instance",
        "admin_peers",
        ["vpn_instance_id", "assigned_ip"],
    )

    _drop_legacy_unique(
        "peers",
        "peers_assigned_ip_key",
        "ix_peers_assigned_ip",
    )
    op.create_unique_constraint(
        "uq_peer_ip_per_site",
        "peers",
        ["site_id", "assigned_ip"],
    )

    op.execute(
        "SELECT setval("
        "pg_get_serial_sequence('vpn_instances','id'), "
        "(SELECT max(id) FROM vpn_instances))"
    )


def downgrade():
    op.drop_constraint(
        "uq_peer_ip_per_site",
        "peers",
        type_="unique",
    )
    op.create_unique_constraint(
        "peers_assigned_ip_key",
        "peers",
        ["assigned_ip"],
    )

    op.drop_constraint(
        "uq_admin_peer_ip_per_instance",
        "admin_peers",
        type_="unique",
    )
    op.create_unique_constraint(
        "admin_peers_assigned_ip_key",
        "admin_peers",
        ["assigned_ip"],
    )

    op.drop_index(
        "ix_admin_peers_vpn_instance_id",
        table_name="admin_peers",
    )
    op.drop_constraint(
        "fk_admin_peers_vpn_instance",
        "admin_peers",
        type_="foreignkey",
    )
    op.drop_column("admin_peers", "vpn_instance_id")

    op.drop_constraint(
        "uq_site_cidr_per_instance",
        "sites",
        type_="unique",
    )
    op.drop_constraint(
        "uq_site_name_per_instance",
        "sites",
        type_="unique",
    )
    op.create_unique_constraint(
        "sites_vpn_cidr_key",
        "sites",
        ["vpn_cidr"],
    )
    op.create_unique_constraint(
        "sites_name_key",
        "sites",
        ["name"],
    )

    op.drop_index(
        "ix_sites_vpn_instance_id",
        table_name="sites",
    )
    op.drop_constraint(
        "fk_sites_vpn_instance",
        "sites",
        type_="foreignkey",
    )
    op.drop_column("sites", "vpn_instance_id")

    op.drop_index(
        "uq_default_vpn_instance",
        table_name="vpn_instances",
    )
    op.drop_table("vpn_instances")
