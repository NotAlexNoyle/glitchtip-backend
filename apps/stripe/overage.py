"""Graduated overage pricing math.

Pure, side-effect-free helpers driven by ``settings.GLITCHTIP_OVERAGE_TIERS``.
Stripe is the system of record for what a customer is actually invoiced; these
functions mirror that schedule locally so we can (a) show an org its projected
overage cost and (b) convert a dollar spend cap into a hard unit ceiling we stop
reporting at. "units" are billable events above the plan quota.
"""

from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal

from django.conf import settings

CENTS = Decimal("1")


def _tiers() -> list[tuple[int | None, Decimal]]:
    """Normalize the settings schedule to (up_to, per_event_cost) Decimals.

    ``up_to`` is the cumulative overage-unit boundary for the tier (None = ∞).
    """
    return [(up_to, Decimal(rate)) for up_to, rate in settings.GLITCHTIP_OVERAGE_TIERS]


def cost_cents_for_units(units: int) -> int:
    """Graduated cost, in integer cents, of ``units`` overage events.

    Each tier prices only the units that fall within its band, summed across
    bands (graduated, not volume). Rounded to the nearest cent at the end.
    """
    if units <= 0:
        return 0
    total = Decimal(0)
    prev = 0
    for up_to, rate in _tiers():
        band_end = units if up_to is None else min(units, up_to)
        band_units = band_end - prev
        if band_units > 0:
            total += Decimal(band_units) * rate
        prev = band_end
        if up_to is not None and units <= up_to:
            break
    cents = (total * 100).quantize(CENTS, rounding=ROUND_HALF_UP)
    return int(cents)


def units_for_budget(cap_cents: int) -> int:
    """Max whole overage units whose graduated cost stays within ``cap_cents``.

    The inverse of :func:`cost_cents_for_units`. Used to turn an org's dollar
    spend cap into the unit ceiling past which we stop reporting meter events,
    so the invoice never exceeds the cap.
    """
    if cap_cents <= 0:
        return 0
    budget = Decimal(cap_cents) / 100
    units = 0
    prev = 0
    for up_to, rate in _tiers():
        if rate <= 0:
            # A free tier: absorb its whole capacity at no cost.
            if up_to is None:
                return units  # unbounded free band — no finite ceiling to add
            units += up_to - prev
            prev = up_to
            continue
        capacity = None if up_to is None else up_to - prev
        affordable = int((budget / rate).to_integral_value(rounding=ROUND_FLOOR))
        if capacity is None or affordable <= capacity:
            return units + affordable
        # Consume the whole band and carry the remaining budget forward.
        units += capacity
        budget -= Decimal(capacity) * rate
        prev = up_to
    return units
