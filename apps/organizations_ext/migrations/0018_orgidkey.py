from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("organizations_ext", "0017_organization_slug_not_all_digits"),
    ]

    operations = [
        migrations.CreateModel(
            name="OrgIdKey",
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
                        condition=models.Q(("id", 1)), name="orgidkey_single_row"
                    )
                ],
            },
        ),
    ]
