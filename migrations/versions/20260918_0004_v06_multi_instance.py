"""VPNHub v0.6 multi-instance runtime

Revision ID: 20260918_0004
Revises: 20260918_0003
"""
revision = "20260918_0004"
down_revision = "20260918_0003"
branch_labels = None
depends_on = None


def upgrade():
    # A estrutura VPNInstance foi criada na v0.5.
    # A v0.6 muda controller/runtime e não exige novas colunas.
    pass


def downgrade():
    pass
