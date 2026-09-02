"""The slug -> org id map, and the property that makes caching it safe.

The map exists so the isolation filter carries a plain int on the nested
``RANGE -> HASH`` partitioned tables, where a scalar subquery is resolved too
late for the planner to prune. See ``glitchtip/api/org_ids.py``.

The reason it is allowed to be stale is structural, not statistical: the gate
requires a membership row whose organization matches BOTH the cached id AND
the request's slug, and ``slug`` is unique. So a wrong id cannot pass the
gate, and the endpoint returns empty instead of another organization's rows.
``StaleEntryFailsClosedTestCase`` states that directly, because it is the
only thing standing between this cache and a cross-tenant leak.
"""

from asgiref.sync import async_to_sync
from django.test import TestCase
from model_bakery import baker

from glitchtip.api import org_ids
from glitchtip.api.org_ids import aresolve_org_id
from glitchtip.api.permissions import OrgScope, _resolve_roles
from glitchtip.test_utils import generators  # noqa: F401


def resolve(slug: str) -> int | None:
    return async_to_sync(aresolve_org_id)(slug)


class ResolveOrgIdTestCase(TestCase):
    def setUp(self):
        org_ids.clear()
        self.organization = baker.make("organizations_ext.Organization")

    def test_resolves_slug_to_id(self):
        self.assertEqual(resolve(self.organization.slug), self.organization.id)

    def test_unknown_slug_is_none(self):
        self.assertIsNone(resolve("no-such-org"))

    def test_unknown_slug_is_not_cached(self):
        """Slugs come from the URL, so an unresolvable one must not consume an
        entry -- otherwise request volume, not organization count, sizes the
        map."""
        resolve("no-such-org")
        self.assertEqual(len(org_ids._cache), 0)

    def test_second_call_does_not_query(self):
        resolve(self.organization.slug)
        with self.assertNumQueries(0):
            self.assertEqual(resolve(self.organization.slug), self.organization.id)

    def test_soft_deleted_org_still_resolves(self):
        """``is_deleted`` is the gate's business. Resolving it here anyway
        keeps deleted orgs off the subquery path, and the gate still refuses
        them."""
        self.organization.is_deleted = True
        self.organization.save(update_fields=["is_deleted"])
        org_ids.clear()
        self.assertEqual(resolve(self.organization.slug), self.organization.id)

    def test_forget_drops_one_entry(self):
        other = baker.make("organizations_ext.Organization")
        resolve(self.organization.slug)
        resolve(other.slug)
        org_ids.forget(self.organization.slug)
        self.assertNotIn(self.organization.slug, org_ids._cache)
        self.assertIn(other.slug, org_ids._cache)

    def test_expired_entry_is_refetched(self):
        resolve(self.organization.slug)
        # Expire in place rather than sleeping.
        org_id, _ = org_ids._cache[self.organization.slug]
        org_ids._cache[self.organization.slug] = (org_id, 0.0)
        with self.assertNumQueries(1):
            self.assertEqual(resolve(self.organization.slug), self.organization.id)

    def test_map_is_bounded(self):
        """A slug per request would otherwise be a slow memory leak."""
        original = org_ids.MAX_ENTRIES
        org_ids.MAX_ENTRIES = 2
        try:
            for _ in range(4):
                resolve(baker.make("organizations_ext.Organization").slug)
            self.assertEqual(len(org_ids._cache), 2)
        finally:
            org_ids.MAX_ENTRIES = original


class StaleEntryFailsClosedTestCase(TestCase):
    """A wrong id returns nothing, never another organization's rows.

    This is the whole safety argument for caching the mapping, and it rests on
    the ``organization__slug`` filter in ``OrgScope.gate`` that looks redundant
    next to ``organization_id``. Both must agree. Don't remove either.
    """

    def setUp(self):
        org_ids.clear()
        self.user = baker.make("users.user")
        self.organization = baker.make("organizations_ext.Organization")
        self.organization.add_user(self.user)
        self.other = baker.make("organizations_ext.Organization")
        self.other.add_user(self.user)

    def scope(self, slug: str, org_id: int | None) -> OrgScope:
        required, roles = _resolve_roles(["org:read"])
        return OrgScope(self.user.id, slug, required, roles, org_id=org_id)

    def gate_passes(self, scope: OrgScope) -> bool:
        from apps.organizations_ext.models import Organization

        return Organization.objects.filter(scope.gate).exists()

    def test_correct_id_passes(self):
        self.assertTrue(
            self.gate_passes(self.scope(self.organization.slug, self.organization.id))
        )

    def test_id_of_another_org_the_user_belongs_to_fails(self):
        """The dangerous case: the stale id names a real organization the
        caller is genuinely a member of. Slug and id still disagree, so the
        gate refuses -- membership in the wrong org is not authorization for
        this one."""
        self.assertFalse(
            self.gate_passes(self.scope(self.organization.slug, self.other.id))
        )

    def test_id_of_a_deleted_org_fails(self):
        """The one case the TTL is for: ``force_delete`` frees a slug and
        another organization takes it. The stale id refuses; the real one
        works, so the window is empty responses, not wrong ones."""
        from apps.organizations_ext.models import Organization

        stale = self.organization.id
        slug = self.organization.slug
        self.organization.force_delete()
        recreated = baker.make("organizations_ext.Organization")
        # OrganizationSlugField repopulates from ``name`` on save, so the slug
        # has to be written past the field to reuse it.
        Organization.objects.filter(id=recreated.id).update(slug=slug)
        recreated.add_user(self.user)

        self.assertFalse(self.gate_passes(self.scope(slug, stale)))
        self.assertTrue(self.gate_passes(self.scope(slug, recreated.id)))
