"""Enforce one active gateway per Site

Revision ID: 20260917_0002
Revises: 20260917_0001
"""
from alembic import op
import sqlalchemy as sa

revision = "20260917_0002"
down_revision = "20260917_0001"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    duplicates = bind.execute(sa.text("""
        SELECT site_id, count(*)
          FROM peers
         WHERE peer_type = 'gateway'
           AND enabled = true
         GROUP BY site_id
        HAVING count(*) > 1
    """)).fetchall()

    if duplicates:
        details = ", ".join(
            f"site_id={site_id} ({count} gateways)"
            for site_id, count in duplicates
        )
        raise RuntimeError(
            "Migração v0.4 interrompida: existem Sites com mais de um "
            f"Gateway ativo: {details}. Desative/remova os excedentes e repita."
        )

    op.create_index(
        "uq_active_gateway_per_site",
        "peers",
        ["site_id"],
        unique=True,
        postgresql_where=sa.text(
            "peer_type = 'gateway' AND enabled = true"
        ),
    )


def downgrade():
    op.drop_index(
        "uq_active_gateway_per_site",
        table_name="peers",
    )
