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
            name="overage_billed_through",
            field=models.PositiveBigIntegerField(
                db_default=0,
                default=0,
                help_text="Cycle usage that overage had billed through by "
                "overage_enabled_at.",
            ),
        ),
    ]
