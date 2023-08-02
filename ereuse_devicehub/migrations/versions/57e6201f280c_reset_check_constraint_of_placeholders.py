"""reset check_constraint of placeholders

Revision ID: 57e6201f280c
Revises: 8ccba3cb37c2
Create Date: 2023-08-02 15:56:12.484340

"""
import sqlalchemy as sa
from alembic import context, op

# revision identifiers, used by Alembic.
revision = '57e6201f280c'
down_revision = '8ccba3cb37c2'
branch_labels = None
depends_on = None


def get_inv():
    INV = context.get_x_argument(as_dictionary=True).get('inventory')
    if not INV:
        raise ValueError("Inventory value is not specified")
    return INV


def upgrade():
    op.drop_constraint(
        'device_depth_check', "device", type_="check", schema=f'{get_inv()}'
    )
    op.drop_constraint(
        'device_height_check', "device", type_="check", schema=f'{get_inv()}'
    )
    op.drop_constraint(
        'device_width_check', "device", type_="check", schema=f'{get_inv()}'
    )
    op.drop_constraint(
        'device_weight_check', "device", type_="check", schema=f'{get_inv()}'
    )
    op.create_check_constraint(
        "device_depth_check",
        "device",
        sa.Column("depth") >= (0.1),
        schema=f'{get_inv()}',
    )
    op.create_check_constraint(
        "device_height_check",
        "device",
        sa.Column("depth") >= (0.1),
        schema=f'{get_inv()}',
    )
    op.create_check_constraint(
        "device_width_check",
        "device",
        sa.Column("depth") >= (0.1),
        schema=f'{get_inv()}',
    )
    op.create_check_constraint(
        "device_weight_check",
        "device",
        sa.Column("depth") >= (0.1),
        schema=f'{get_inv()}',
    )


def downgrade():
    pass
