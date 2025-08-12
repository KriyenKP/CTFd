"""Add registry fields to docker_config table"""

revision = "addregistry001"
down_revision = "f73a96c97449"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("docker_config", sa.Column("registry_url", sa.String(length=255), nullable=True))
    op.add_column("docker_config", sa.Column("registry_username", sa.String(length=255), nullable=True))
    op.add_column("docker_config", sa.Column("registry_password", sa.String(length=255), nullable=True))
    op.add_column("docker_config", sa.Column("use_registry", sa.Boolean(), nullable=True))


def downgrade():
    op.drop_column("docker_config", "use_registry")
    op.drop_column("docker_config", "registry_password")
    op.drop_column("docker_config", "registry_username")
    op.drop_column("docker_config", "registry_url")
