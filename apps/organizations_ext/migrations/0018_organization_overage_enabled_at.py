from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("organizations_ext", "0017_organization_slug_not_all_digits"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="overage_enabled_at",
            field=models.DateTimeField(
                blank=True,
                help_text="When overage was last switched on or its cap raised.",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="overage_carried_units",
            field=models.PositiveBigIntegerField(
                default=0,
                help_text="Overage units that cycle had billed by overage_enabled_at.",
            ),
        ),
    ]
