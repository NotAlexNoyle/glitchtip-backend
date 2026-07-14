"""Provision the Stripe objects metered overage billing needs.

Idempotent and **test-mode only**: it refuses to run unless STRIPE_SECRET_KEY
is an ``sk_test`` key, so it can never mutate a live Stripe account. It creates
(or reuses):

1. a Billing Meter for ``GLITCHTIP_OVERAGE_METER_EVENT_NAME``;
2. an overage product (metadata ``product_type=overage``) with a graduated,
   metered price built from ``GLITCHTIP_OVERAGE_TIERS``;
3. a base "Small" hosted plan, if no hosted plan exists yet, so there's
   something to attach overage to during local end-to-end testing.

Then it syncs everything into the local DB via ``sync_stripe_models``.
"""

import json

from asgiref.sync import async_to_sync
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.stripe.client import (
    create_meter,
    create_metered_price,
    create_product,
    find_meter,
    list_prices,
    list_products,
    stripe_post,
)
from apps.stripe.maintenance import sync_stripe_models


async def _find_product_by_type(product_type: str):
    async for page in list_products():
        for product in page:
            if product.metadata.get("product_type", "").lower() == product_type:
                return product
    return None


async def _find_metered_price(product_id: str, meter_id: str):
    async for page in list_prices():
        for price in page:
            recurring = price.recurring or {}
            if price.product == product_id and recurring.get("meter") == meter_id:
                return price
    return None


async def _provision(stdout) -> None:
    # Defense in depth: this function creates real Stripe objects, so guard the
    # test-key check here too, not only at the command entry point.
    if not (settings.STRIPE_SECRET_KEY or "").startswith("sk_test"):
        raise CommandError("Refusing to provision against a non-test Stripe key.")

    event_name = settings.GLITCHTIP_OVERAGE_METER_EVENT_NAME

    # 1. Billing Meter
    meter = await find_meter(event_name)
    if meter is None:
        meter = await create_meter("GlitchTip Overage Events", event_name)
        stdout(f"Created meter {meter.id} ({event_name})")
    else:
        stdout(f"Reusing meter {meter.id} ({event_name})")

    # 2. Overage product + graduated metered price
    product = await _find_product_by_type("overage")
    if product is None:
        product_id = await create_product(
            "GlitchTip Overage",
            metadata={"product_type": "overage"},
            description="Usage-based charges for events above your plan quota.",
        )
        stdout(f"Created overage product {product_id}")
    else:
        product_id = product.id
        stdout(f"Reusing overage product {product_id}")

    price = await _find_metered_price(product_id, meter.id)
    if price is None:
        price = await create_metered_price(
            product_id,
            meter.id,
            settings.GLITCHTIP_OVERAGE_TIERS,
            nickname="GlitchTip overage (graduated)",
        )
        await stripe_post(f"products/{product_id}", {"default_price": price.id})
        stdout(f"Created metered overage price {price.id}")
    else:
        stdout(f"Reusing metered overage price {price.id}")

    # 3. A base hosted plan to attach overage to (for local testing only).
    hosted = await _find_product_by_type("hosted")
    if hosted is None:
        base_id = await create_product(
            "GlitchTip Small (test)",
            metadata={
                "product_type": "hosted",
                "events": "100000",
                "is_public": "true",
            },
            description="Up to 100k events per month.",
        )
        base_price = await stripe_post(
            "prices",
            {
                "product": base_id,
                "currency": "usd",
                "unit_amount": 1500,
                "recurring[interval]": "month",
                "nickname": "GlitchTip Small (test)",
                "metadata[is_public]": "true",
            },
        )
        base_price_id = json.loads(base_price)["id"]
        await stripe_post(f"products/{base_id}", {"default_price": base_price_id})
        stdout(f"Created base hosted plan {base_id} / price {base_price_id}")
    else:
        stdout(f"Found existing hosted plan {hosted.id}")

    await sync_stripe_models()
    stdout("Synced Stripe products/prices/subscriptions into the database.")


class Command(BaseCommand):
    help = (
        "Provision (idempotently) the Stripe meter/product/price for overage billing."
    )

    def handle(self, *args, **options):
        key = settings.STRIPE_SECRET_KEY or ""
        if not key.startswith("sk_test"):
            raise CommandError(
                "Refusing to run: STRIPE_SECRET_KEY is not a test key (sk_test...). "
                "This command must only touch a Stripe test account."
            )
        async_to_sync(_provision)(lambda msg: self.stdout.write(msg))
        self.stdout.write(self.style.SUCCESS("Overage billing provisioned."))
