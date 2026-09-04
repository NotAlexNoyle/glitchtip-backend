from django.db import migrations, models
from django.db.models import Max, Sum


def carry_counters_to_organization(apps, schema_editor):
    """Move each org's overage counter off its subscriptions.

    Sums the counters sharing the org's latest anchor rather than taking the
    primary subscription's. The meter aggregates per customer, so if a second
    subscription ever became primary mid-cycle both counters describe units
    Stripe already holds, and only their sum bounds what it has recorded.
    Erring high can at worst leave a delta unbilled; erring low re-reports it.
    """
    Organization = apps.get_model("organizations_ext", "Organization")
    StripeSubscription = apps.get_model("stripe", "StripeSubscription")

    anchors = (
        StripeSubscription.objects.filter(overage_period_start__isnull=False)
        .values("organization")
        .annotate(anchor=Max("overage_period_start"))
    )
    for row in anchors:
        total = StripeSubscription.objects.filter(
            organization=row["organization"], overage_period_start=row["anchor"]
        ).aggregate(total=Sum("overage_units_reported"))["total"]
        Organization.objects.filter(pk=row["organization"]).update(
            overage_units_reported=total or 0,
            overage_period_start=row["anchor"],
        )


def carry_counters_back(apps, schema_editor):
    """Reverse onto the primary subscription, which is the one that reports."""
    Organization = apps.get_model("organizations_ext", "Organization")
    StripeSubscription = apps.get_model("stripe", "StripeSubscription")

    for org in Organization.objects.filter(
        overage_period_start__isnull=False, stripe_primary_subscription__isnull=False
    ):
        StripeSubscription.objects.filter(pk=org.stripe_primary_subscription_id).update(
            overage_units_reported=org.overage_units_reported,
            overage_period_start=org.overage_period_start,
        )


class Migration(migrations.Migration):
    dependencies = [
        ("organizations_ext", "0014_organization_member_guard"),
        ("stripe", "0020_stripeproduct_uptime_monitors"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="overage_period_start",
            field=models.DateTimeField(
                blank=True,
                help_text="Cycle anchor for overage_units_reported; counter "
                "resets when the current cycle start moves past this.",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="organization",
            name="overage_units_reported",
            field=models.PositiveBigIntegerField(
                default=0,
                help_text="Cumulative billable overage events reported to the "
                "meter this cycle. Meter events are additive, so we report deltas.",
            ),
        ),
        migrations.RunPython(
            carry_counters_to_organization, carry_counters_back, elidable=False
        ),
    ]
