import secrets

from django.db import migrations, models


def create_key(apps, schema_editor):
    """Create the public id key, once.

    Must survive squashes (RunPython is not elidable): a fresh database gets
    its key from here. Running processes create one too if the row is
    missing, so this never replaces a row that exists.
    """
    PublicIdKey = apps.get_model("organizations_ext", "PublicIdKey")
    PublicIdKey.objects.bulk_create(
        [PublicIdKey(id=1, key=secrets.token_hex(32))], ignore_conflicts=True
    )


class Migration(migrations.Migration):
    dependencies = [
        ("organizations_ext", "0017_organization_slug_not_all_digits"),
    ]

    # One migration, so one transaction: other processes see either no table
    # or the table with its key row, never an empty table.
    operations = [
        migrations.CreateModel(
            name="PublicIdKey",
            fields=[
                (
                    "id",
                    models.PositiveSmallIntegerField(
                        default=1, primary_key=True, serialize=False
                    ),
                ),
                ("key", models.CharField(max_length=64)),
            ],
            options={
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(("id", 1)), name="publicidkey_single_row"
                    )
                ],
            },
        ),
        # Unapplying drops the table, key included; nothing to undo here.
        migrations.RunPython(create_key, migrations.RunPython.noop),
    ]
