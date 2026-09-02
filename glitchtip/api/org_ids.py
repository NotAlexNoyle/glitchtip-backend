"""Organization slug -> id, resolved once per worker instead of per query.

``OrgScope`` can put the org id into the isolation filter two ways: as a
scalar subquery on the slug, or as a Python int. The subquery is the default
and is right for almost everything -- see ``OrgScope.org_id_expr``. This
module exists for the tables where it isn't.

On the nested ``RANGE -> HASH`` partitioned tables -- issue events, logs,
spans -- a subquery's value arrives via ``InitPlan``, which runs *after*
``ExecInitAppend``. That is too late for pruning at executor init, so every
leaf stays in the plan, gets initialised, and gets locked. With an int the
planner emits ``Subplans Removed`` and never opens the rest. On a table with
``retention_days x PARTITION_HASH_BUCKETS`` leaves that is the difference
between one hash bucket and all of them, and it spends the
``max_locks_per_transaction`` budget we already have documented problems with.

Slug-to-id is global, tiny, and nearly immutable, so a small in-process map
per worker is enough: a cold miss costs one extra query per slug per worker
and then it is free. It deliberately does not use Valkey or the cache
framework -- those are a network hop, and the hop is the thing the folded
gate exists to remove.

A stale entry here cannot leak another organization's rows. The isolation
filter uses this id, and ``OrgScope.gate`` independently requires a
membership row whose organization has BOTH this id AND the request's slug.
``slug`` is unique, so a passing gate proves the id is the right one; a wrong
id means the ``EXISTS`` fails and the endpoint returns empty. That is why the
redundant-looking ``organization__slug`` filter in the gate is not redundant.
"""

from collections import OrderedDict
from time import monotonic

from apps.organizations_ext.models import Organization

# Bounded because callers name the slug in the URL and can name anything, so
# the map must not grow with request volume. Misses are never stored, for the
# same reason: an unresolvable slug is not a fact worth remembering.
MAX_ENTRIES = 4096

# Not a correctness bound -- see the module docstring; nothing here can grant
# access. It bounds the one liveness case the fail-closed property doesn't
# cover: a slug freed by ``force_delete`` and then registered by a different
# organization, where the stale id would otherwise return empty forever.
# Renames don't need it (the new slug is a miss, and the old slug names
# nothing), and soft deletes don't either (the gate checks ``is_deleted``).
TTL_SECONDS = 300.0

_cache: "OrderedDict[str, tuple[int, float]]" = OrderedDict()


async def aresolve_org_id(slug: str) -> int | None:
    """The id for ``slug``, or ``None`` if no organization has it.

    ``None`` leaves ``OrgScope.org_id`` unset, which falls back to the scalar
    subquery -- correct, and the gate fails anyway.
    """
    now = monotonic()
    hit = _cache.get(slug)
    if hit is not None:
        org_id, expires = hit
        if expires > now:
            _cache.move_to_end(slug)
            return org_id
        del _cache[slug]

    # No ``is_deleted`` filter: the gate checks it, and excluding deleted orgs
    # here would push them onto the subquery path for no gain.
    org_id = (
        await Organization.objects.filter(slug=slug)
        .values_list("id", flat=True)
        .afirst()
    )
    if org_id is None:
        return None

    _cache[slug] = (org_id, now + TTL_SECONDS)
    while len(_cache) > MAX_ENTRIES:
        _cache.popitem(last=False)
    return org_id


def forget(slug: str) -> None:
    """Drop one entry. This worker only -- other workers wait out the TTL."""
    _cache.pop(slug, None)


def clear() -> None:
    """Drop everything. Called between tests; see ``glitchtip/test_runner.py``."""
    _cache.clear()
