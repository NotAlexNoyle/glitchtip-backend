"""Safety net for the Auth / OrgAuth divide.

The rescope splits one object in two:

- ``Auth`` (``glitchtip/api/authentication.py``) answers *who are you*. It
  carries a user id, how they authenticated, and the token if there was one.
  Nothing else. It cannot answer a permission question and must not try.
- ``OrgAuth`` (``glitchtip/api/permissions.py``) answers *what can you do
  here*. It only exists as the return value of ``resolve_org_auth``, which
  builds it from a real ``OrganizationUser`` row and refuses -- returning
  ``OrgAuthError`` -- when the caller is not a member or holds none of the
  required scopes.

Views drop their own membership filters and read ``scoped_org_id(request)``
instead. That is only safe if holding an ``OrgAuth`` really is proof that
authorization ran and passed, so these tests pin the divide itself:

- ``AuthCarriesNoAuthorizationTestCase`` pins the split structurally. If
  ``Auth`` regrows a scope or an org id, a view can reach an organization
  without a permission check ever having run.
- ``OrgAuthIsProofOfAuthorizationTestCase`` states the invariant the ported
  querysets rest on: an ``OrgAuth`` implies membership and a resolved org id,
  and there is no way to get an org id out of a refusal. It also pins the two
  role values apart -- ``role`` is the int views annotate onto querysets,
  ``role_details`` the ``ROLES`` entry the messages read.
- ``DecoratorIsTheBoundaryTestCase`` reads the source tree and asserts no
  route reaches for ``scoped_org_id`` without ``@has_permission`` above it --
  the static form of "a route that forgot its decorator must not serve
  everything" -- and that every ``actor_role=`` a caller passes is the int off
  the resolved ``OrgAuth``.
- ``CrossOrgIsolationTestCase`` walks every route family with a foreign
  organization slug and asserts 403. Written against URLs rather than
  querysets on purpose, so it keeps working no matter which layer filters.
- ``ScopedQueryCountTestCase`` locks in the query counts the port is for, so a
  later change cannot quietly reintroduce a round trip.
- ``TokenCeilingEndToEndTestCase`` is the HTTP-level version of the token
  ceiling: a token is capped by its owner's role, and now also by membership.

Scope arithmetic and 403 wording live next door in
``glitchtip/test_scope_resolution.py`` and
``glitchtip/test_permission_messages.py``. What is asserted here is only the
part the ported querysets depend on: that an organization id cannot be
obtained without an authorization check.
"""

import ast
import pathlib
import re

from asgiref.sync import sync_to_async
from django.db import connection
from django.db.models import IntegerField
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from model_bakery import baker

from apps.organizations_ext.constants import OrganizationUserRole
from glitchtip.api.authentication import Auth, ScopeNotResolved
from glitchtip.api.permissions import (
    OrgAuth,
    OrgAuthError,
    resolve_org_auth,
    scoped_org_id,
)
from glitchtip.api.scopes import SCOPES
from glitchtip.test_utils import generators  # noqa: F401
from glitchtip.test_utils.test_case import GlitchTestCase

ORGUSER_TABLE = "organizations_ext_organizationuser"
ORG_TABLE = "organizations_ext_organization"

BACKEND_ROOT = pathlib.Path(__file__).resolve().parent.parent

# get_organization's scopes -- the widest of the org-read routes.
ORG_READ = frozenset({"org:read", "org:write", "org:admin"})
# delete_organization's scope -- owner only.
ORG_ADMIN = frozenset({"org:admin"})


def make_org_fixture(role=OrganizationUserRole.ADMIN):
    """A whole organization with one member and one of everything under it."""
    project = baker.make("projects.Project", organization__scrub_ip_addresses=False)
    org = project.organization
    user = baker.make("users.user")
    org_user = org.add_user(user, role)
    team = baker.make("teams.Team", organization=org)
    team.members.add(org_user)
    project.teams.add(team)
    issue = baker.make("issue_events.Issue", project=project)
    baker.make("issue_events.Comment", issue=issue, user=user, text="a comment")
    baker.make("issue_events.UserReport", issue=issue, project=project)
    release = baker.make("releases.Release", organization=org, version="1.0.0")
    release.projects.add(project)
    environment = baker.make("environments.Environment", organization=org, name="prod")
    baker.make(
        "environments.EnvironmentProject", environment=environment, project=project
    )
    baker.make("alerts.ProjectAlert", project=project)
    return {
        "org": org,
        "user": user,
        "org_user": org_user,
        "project": project,
        "team": team,
        "issue": issue,
        "release": release,
        "environment": environment,
    }


class AuthCarriesNoAuthorizationTestCase(TestCase):
    """``Auth`` is identity. The divide is only real while that stays true.

    These read as trivia until someone adds a convenience property back onto
    ``Auth`` -- at which point a view can obtain an organization without any
    permission check having run, which is exactly the failure the split exists
    to make impossible.
    """

    AUTHORIZATION_SURFACE = (
        "scope",
        "scopes",
        "org_id",
        "organization_id",
        "role",
        # The name the role actually went by while it lived on ``Auth``. Views
        # still pass it as ``actor_role=``, so this is the one a half-finished
        # revert is most likely to put back.
        "actor_role",
        "role_details",
        "resolve_scope",
        "has_scope",
    )

    def test_auth_exposes_identity_and_nothing_more(self):
        auth = Auth(1, "session")
        for name in self.AUTHORIZATION_SURFACE:
            with self.subTest(attribute=name):
                self.assertFalse(
                    hasattr(auth, name),
                    f"Auth grew {name!r}; authorization belongs on OrgAuth, "
                    "which only exists once a permission check has passed",
                )

    def test_auth_fields_are_exactly_identity(self):
        self.assertEqual(
            sorted(Auth.__dataclass_fields__), ["auth_type", "token", "user_id"]
        )

    def test_a_token_on_auth_is_the_credential_not_a_grant(self):
        """The token rides along on ``Auth`` so ``resolve_org_auth`` can read
        its scopes. Holding it is not itself permission to do anything."""
        token = baker.make("api_tokens.APIToken", user=baker.make("users.user"))
        token.add_permissions(list(SCOPES))
        auth = Auth(token.user_id, "token", token=token)
        self.assertFalse(hasattr(auth, "org_id"))
        self.assertFalse(hasattr(auth, "scope"))


class OrgAuthIsProofOfAuthorizationTestCase(TestCase):
    """The invariant the ported querysets rest on.

    Every view that dropped its membership filter relies on this: if
    ``@has_permission`` did not raise, ``scoped_org_id()`` returns an
    organization the actor belongs to. Break it and those querysets stop being
    scoped at all.
    """

    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization")
        # The first user added becomes the owner, so seed a throwaway one to
        # get a genuine non-owner membership below.
        cls.org.add_user(baker.make("users.user"), OrganizationUserRole.OWNER)
        cls.member = baker.make("users.user")
        cls.org.add_user(cls.member, OrganizationUserRole.MEMBER)
        cls.stranger = baker.make("users.user")

    async def test_member_resolves_own_org(self):
        result = await resolve_org_auth(
            Auth(self.member.id, "session"), ORG_READ, self.org.slug
        )
        self.assertIsInstance(result, OrgAuth)
        self.assertEqual(result.org_id, self.org.id)

    async def test_the_role_is_two_values_and_they_are_not_interchangeable(self):
        """``role`` is the int; ``role_details`` is the ``ROLES`` entry.

        The two are one field apart and both answer "what role is this", which
        is exactly why they get swapped. They are not substitutable in either
        direction: ``role`` is what views hand to querysets as ``actor_role``
        and lands in ``Value(actor_role, IntegerField())``, while
        ``role_details`` is what the scope arithmetic and the 403 messages
        subscript. Passing the dict where the int belongs fails at SQL compile
        time; passing the int where the dict belongs is a ``TypeError``.
        """
        result = await resolve_org_auth(
            Auth(self.member.id, "session"), ORG_READ, self.org.slug
        )
        self.assertEqual(result.role, OrganizationUserRole.MEMBER)
        self.assertNotIsInstance(result.role, dict)
        self.assertEqual(
            result.role_details,
            OrganizationUserRole.get_role(OrganizationUserRole.MEMBER),
        )
        # The one that the annotation cares about: an int survives IntegerField.
        self.assertEqual(
            IntegerField().get_prep_value(result.role), OrganizationUserRole.MEMBER
        )
        with self.assertRaises(TypeError):
            IntegerField().get_prep_value(result.role_details)

    async def test_non_member_is_refused_and_the_refusal_carries_no_org_id(self):
        """Both halves are the invariant. The refusal means
        ``has_permission`` raises 403; the absent org id means a view that
        somehow ran anyway still cannot widen its queryset."""
        result = await resolve_org_auth(
            Auth(self.stranger.id, "session"), ORG_READ, self.org.slug
        )
        self.assertIsInstance(result, OrgAuthError)
        self.assertFalse(
            hasattr(result, "org_id"),
            "a refusal must not hand back the organization it refused",
        )

    async def test_member_short_a_scope_is_refused_and_carries_no_org_id(self):
        """Membership alone is not authorization. A MEMBER who cannot delete
        the organization must not come back holding its id either."""
        result = await resolve_org_auth(
            Auth(self.member.id, "session"), ORG_ADMIN, self.org.slug
        )
        self.assertIsInstance(result, OrgAuthError)
        self.assertTrue(result.membership)
        self.assertFalse(hasattr(result, "org_id"))

    async def test_non_member_token_is_refused_however_scoped(self):
        """The strengthening the divide bought.

        Under the old model a token supplied its own scopes independently of
        any organization, so a fully scoped token *cleared the scope check* on
        an org it had nothing to do with -- only the separate org-id lookup
        stopped it. Now membership is resolved first and a non-member token is
        refused outright.
        """
        token = await baker.amake("api_tokens.APIToken", user=self.stranger)
        await sync_to_async(token.add_permissions)(list(SCOPES))
        result = await resolve_org_auth(
            Auth(token.user_id, "token", token=token), ORG_READ, self.org.slug
        )
        self.assertIsInstance(result, OrgAuthError)
        self.assertFalse(result.membership)

    async def test_a_resolved_org_id_is_always_concrete(self):
        """Views may filter on ``scoped_org_id`` unguarded.

        ``resolve_org_auth`` either returns an ``OrgAuth`` built from a real
        membership row or it returns an error, so there is no such thing as an
        authorized request with an unknown organization. Any ``is None`` branch
        a view still carries around ``scoped_org_id`` is dead code.
        """

        class FakeRequest:
            pass

        request = FakeRequest()
        request.org_auth = await resolve_org_auth(
            Auth(self.member.id, "session"), ORG_READ, self.org.slug
        )
        self.assertEqual(scoped_org_id(request), self.org.id)
        self.assertIsNotNone(scoped_org_id(request))

    def test_unresolved_request_raises_rather_than_returning_none(self):
        """A view that forgot its decorator must fail loudly, not serve
        everything.

        ``request.org_auth`` is set by ``has_permission`` and by nothing else,
        so reading it on an unchecked request has to blow up. What matters to
        the ported querysets is that it never quietly yields ``None`` --
        ``filter(organization_id=None)`` matches nothing today but says
        nothing about intent, and any future ``if org_id is None`` fallback
        would silently widen.

        ``ScopeNotResolved`` is the named exception for this and is still
        defined in ``authentication.py``, but nothing raises it since the
        split, so today the missing attribute is what fails. Either is loud
        enough; returning ``None`` is not.
        """

        class FakeRequest:
            auth = Auth(1, "session")

        with self.assertRaises((ScopeNotResolved, AttributeError)):
            scoped_org_id(FakeRequest())

    def test_a_bare_org_auth_yields_nothing(self):
        """``OrgAuth`` is only meaningful once ``resolve_org_auth`` fills it.

        It is a plain class with annotations rather than a dataclass, so an
        instance nobody populated has no ``org_id`` at all. That is what makes
        "holding an OrgAuth" equivalent to "a check passed" -- there is no
        default to fall back to.
        """
        bare = OrgAuth()
        for name in ("org_id", "scope", "role", "role_details"):
            with self.subTest(attribute=name):
                self.assertFalse(hasattr(bare, name))


class DecoratorIsTheBoundaryTestCase(TestCase):
    """``@has_permission`` is the only thing that sets ``request.org_auth``.

    The runtime tests above prove an unchecked request cannot produce an
    organization id. These read the source tree and prove no route is in a
    position to try, and that the ones that are gated read the resolved object
    rather than something that merely looks like it. A missing decorator is a
    mistake caught at import time by reading the code, not at 3am by reading a
    leak report.
    """

    @staticmethod
    def _decorator_names(fn: ast.AST) -> list[str]:
        names = []
        for dec in fn.decorator_list:
            node = dec.func if isinstance(dec, ast.Call) else dec
            while isinstance(node, ast.Attribute):
                node = node.value
            if isinstance(node, ast.Name):
                names.append(node.id)
        return names

    @staticmethod
    def _is_route(fn: ast.AST) -> bool:
        for dec in fn.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and isinstance(dec.func.value, ast.Name)
                and dec.func.value.id == "router"
            ):
                return True
        return False

    @classmethod
    def routes(cls):
        """Every ``@router.*`` handler under ``apps/``, with what we need."""
        for path in sorted(BACKEND_ROOT.glob("apps/**/*.py")):
            if "/tests/" in str(path) or "/migrations/" in str(path):
                continue
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:  # pragma: no cover -- defensive
                continue
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not cls._is_route(fn):
                    continue
                params = [a.arg for a in fn.args.args + fn.args.kwonlyargs]
                yield (
                    str(path.relative_to(BACKEND_ROOT)),
                    fn.name,
                    cls._decorator_names(fn),
                    params,
                    ast.unparse(fn),
                )

    def test_no_route_reads_scoped_org_id_without_the_decorator(self):
        """The hard invariant: reaching for the resolved org id without having
        resolved it is a 500 waiting to happen, and the decorator is what
        resolves it."""
        offenders = [
            f"{path}::{name}"
            for path, name, decorators, _params, source in self.routes()
            if "scoped_org_id" in source and "has_permission" not in decorators
        ]
        self.assertEqual(
            offenders,
            [],
            "route(s) read scoped_org_id() with no @has_permission to set it",
        )

    def test_org_scoped_routes_are_gated(self):
        """A ledger, not a wall.

        A route that takes an ``organization_slug`` is addressing one
        organization's data, so it should be gated. The apps below are not
        ported yet -- they still carry their own membership filters. Shrink
        this list as they land; a *new* name appearing in the diff is the
        regression this test is for.
        """
        expected_ungated = {
            "apps/stripe/api.py::configure_overage",
            "apps/stripe/api.py::create_stripe_session",
            "apps/stripe/api.py::get_overage_status",
            "apps/stripe/api.py::get_stripe_subscription",
            "apps/stripe/api.py::stripe_billing_portal_session",
            "apps/stripe/api.py::subscription_events_count_daily",
            "apps/stripe/api.py::subscription_events_count_for_period",
            "apps/uptime/api.py::create_monitor",
            "apps/uptime/api.py::create_status_page",
            "apps/uptime/api.py::delete_monitor",
            "apps/uptime/api.py::get_monitor",
            "apps/uptime/api.py::heartbeat_check",
            "apps/uptime/api.py::list_monitor_checks",
            "apps/uptime/api.py::list_monitors",
            "apps/uptime/api.py::list_status_pages",
            "apps/uptime/api.py::update_monitor",
        }
        ungated = {
            f"{path}::{name}"
            for path, name, decorators, params, _source in self.routes()
            if "organization_slug" in params and "has_permission" not in decorators
        }
        self.assertEqual(
            ungated,
            expected_ungated,
            "an org-scoped route gained or lost its @has_permission",
        )

    # ``queryset_utils`` is where ``actor_role`` is consumed rather than
    # supplied, so its own ``annotate(actor_role=...)`` calls are not call
    # sites and are excluded below.
    ACTOR_ROLE_SINK = "apps/organizations_ext/queryset_utils.py"

    def actor_role_arguments(self):
        """Every ``actor_role=`` a caller passes in, with where it came from."""
        for path in sorted(BACKEND_ROOT.glob("apps/**/*.py")):
            rel = str(path.relative_to(BACKEND_ROOT))
            if "/tests/" in rel or "/migrations/" in rel or rel == self.ACTOR_ROLE_SINK:
                continue
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:  # pragma: no cover -- defensive
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg == "actor_role":
                        yield rel, ast.unparse(kw.value)

    def test_every_caller_passes_the_role_int_off_org_auth(self):
        """The role reaches querysets as the int, from the checked object.

        Two ways to get this wrong, and the tree has held both. Reading it off
        ``Auth`` (``request.auth.actor_role``) is how the pre-split field
        lingers after the field is gone, which is an ``AttributeError``. Reading
        ``role_details`` instead of ``role`` hands over the ``ROLES`` dict,
        which reaches ``Value(actor_role, IntegerField())`` and dies at SQL
        compile time -- past the decorator, so it reads as a working
        permission check right up until the query runs.

        Both are one attribute away from correct and neither is visible at
        import time, so this pins the spelling rather than the behaviour.
        """
        wrong = {
            f"{path}: actor_role={source}"
            for path, source in self.actor_role_arguments()
            if source != "request.org_auth.role"
        }
        self.assertEqual(
            wrong,
            set(),
            "actor_role must be the int on the resolved OrgAuth",
        )

    def test_the_call_sites_are_still_there(self):
        """Guard against the test above passing because it found nothing."""
        self.assertGreaterEqual(len(list(self.actor_role_arguments())), 6)


class CrossOrgIsolationTestCase(GlitchTestCase):
    """A member of one organization must not reach another's resources.

    Both organizations are fully populated, so a route that leaks returns a
    real object rather than an empty list -- an empty foreign fixture would
    pass even with the filtering removed.

    The expected answer is now 403 and only 403. Under the old model a
    non-member fell through to a membership-scoped queryset and got 404, so
    "refused" meant "403 or 404". ``resolve_org_auth`` refuses non-membership
    before the view runs, so the vaguer assertion no longer describes the
    system.
    """

    @classmethod
    def setUpTestData(cls):
        cls.mine = make_org_fixture()
        cls.theirs = make_org_fixture()
        cls.user = cls.mine["user"]

    def setUp(self):
        self.client.force_login(self.user)

    def foreign_urls(self):
        """Every route family, addressed at the organization we do not belong to."""
        f = self.theirs
        org = f["org"].slug
        project = f["project"].slug
        team = f["team"].slug
        issue = f["issue"].id
        routes = {
            "organization": ("api:get_organization", [org], ""),
            "members": ("api:list_organization_members", [org], ""),
            "projects": ("api:list_organization_projects", [org], ""),
            "project": ("api:get_project", [org, project], ""),
            "project keys": ("api:list_project_keys", [org, project], ""),
            "teams": ("api:list_teams", [org], ""),
            "team": ("api:get_team", [org, team], ""),
            "issues": ("api:list_issues", [org], ""),
            "project issues": ("api:list_project_issues", [org, project], ""),
            "issue": ("api:get_organization_issue", [org, issue], ""),
            "issue events": ("api:list_organization_issue_event", [org, issue], ""),
            "comments": ("api:list_organization_comments", [org, issue], ""),
            "user reports": ("api:list_organization_user_reports", [org, issue], ""),
            "releases": ("api:list_releases", [org], ""),
            "environments": ("api:list_environments", [org], ""),
            "alerts": ("api:list_project_alerts", [org, project], ""),
            # issue_stats reads its issue ids from the query string.
            "issue stats": ("api:issue_stats", [org], f"?groups={issue}"),
        }
        return {
            label: reverse(name, args=args) + query
            for label, (name, args, query) in routes.items()
        }

    def test_foreign_org_is_refused_with_403(self):
        for label, url in self.foreign_urls().items():
            with self.subTest(route=label):
                res = self.client.get(url)
                self.assertEqual(
                    res.status_code,
                    403,
                    f"{label} answered {res.status_code} for a foreign "
                    "organization; the decorator should have refused it",
                )

    def test_foreign_org_returns_no_rows(self):
        """The weaker property, kept as a second line of defence. If a route
        ever answers 200 here, it must at least not hand over rows."""
        for label, url in self.foreign_urls().items():
            with self.subTest(route=label):
                res = self.client.get(url)
                if res.status_code != 200:
                    continue
                body = res.json()
                self.assertEqual(
                    body if isinstance(body, list) else [body],
                    [],
                    f"{label} returned a foreign organization's rows",
                )

    def test_a_foreign_org_and_a_missing_one_are_indistinguishable(self):
        """``resolve_org_auth`` cannot tell the two apart -- one absent
        ``OrganizationUser`` row covers both -- and the response must not
        either, or the difference confirms the organization exists."""
        foreign = self.client.get(
            reverse("api:get_organization", args=[self.theirs["org"].slug])
        )
        missing = self.client.get(
            reverse("api:get_organization", args=["no-such-organization"])
        )
        self.assertEqual(foreign.status_code, missing.status_code)
        self.assertEqual(foreign.json()["detail"], missing.json()["detail"])

    def test_own_org_still_works(self):
        """The negative tests above would also pass if every route 403'd."""
        f = self.mine
        for name, args in (
            ("api:get_organization", [f["org"].slug]),
            ("api:list_organization_projects", [f["org"].slug]),
            ("api:list_teams", [f["org"].slug]),
            ("api:list_issues", [f["org"].slug]),
        ):
            with self.subTest(route=name):
                res = self.client.get(reverse(name, args=args))
                self.assertEqual(res.status_code, 200)


class ScopedQueryCountTestCase(GlitchTestCase):
    """Locks in what the port bought, so it cannot be undone by accident.

    Two costs are tracked separately. ``auth_lookups`` counts queries that only
    touch the organization tables -- ``resolve_org_auth`` issues exactly one,
    and any more is a view re-deriving what ``OrgAuth`` already handed it.
    ``member_joins`` counts *data* queries dragged through
    ``organizations_ext_organizationuser``.

    Not every membership join is removable: team member lists and ``is_member``
    annotations are payload, not authorization. So the numbers below are
    recorded observations rather than a target of zero, and they are expected
    to fall as the port proceeds. Update them when they do -- a drop is the
    result, and a rise needs explaining.
    """

    # route -> (total queries, auth lookups, membership joins on data queries)
    EXPECTED: dict[str, tuple[int, int, int]] = {
        "list_issues": (2, 1, 1),
        "list_organization_projects": (3, 1, 1),
        "list_teams": (3, 1, 2),
        "list_organization_members": (3, 1, 1),
        "get_project": (2, 1, 1),
        "list_project_keys": (2, 1, 0),
        "get_organization_issue": (2, 1, 1),
        "list_organization_issue_event": (2, 1, 0),
        "list_project_issues": (2, 1, 1),
        "list_organization_user_reports": (2, 1, 0),
        "get_team": (3, 1, 2),
        "get_organization_member": (4, 1, 1),
    }

    @classmethod
    def setUpTestData(cls):
        cls.create_user()
        cls.issue = baker.make("issue_events.Issue", project=cls.project)

    def setUp(self):
        self.client.force_login(self.user)

    def measure(self, url):
        with CaptureQueriesContext(connection) as ctx:
            res = self.client.get(url)
        self.assertEqual(res.status_code, 200)
        auth_lookups = member_joins = 0
        for query in ctx.captured_queries:
            sql = " ".join(query["sql"].split())
            tables = {
                t
                for pair in re.findall(r'FROM "(\w+)"|JOIN "(\w+)"', sql)
                for t in pair
                if t
            }
            if tables and tables <= {ORGUSER_TABLE, ORG_TABLE}:
                auth_lookups += 1
            elif ORGUSER_TABLE in tables:
                member_joins += 1
        return len(ctx.captured_queries), auth_lookups, member_joins

    def urls(self):
        return {
            "list_issues": reverse("api:list_issues", args=[self.organization.slug]),
            "list_organization_projects": reverse(
                "api:list_organization_projects", args=[self.organization.slug]
            ),
            "list_teams": reverse("api:list_teams", args=[self.organization.slug]),
            "list_organization_members": reverse(
                "api:list_organization_members", args=[self.organization.slug]
            ),
            "get_project": reverse(
                "api:get_project", args=[self.organization.slug, self.project.slug]
            ),
            "list_project_keys": reverse(
                "api:list_project_keys",
                args=[self.organization.slug, self.project.slug],
            ),
            "get_organization_issue": reverse(
                "api:get_organization_issue",
                args=[self.organization.slug, self.issue.id],
            ),
            "list_organization_issue_event": reverse(
                "api:list_organization_issue_event",
                args=[self.organization.slug, self.issue.id],
            ),
            "list_project_issues": reverse(
                "api:list_project_issues",
                args=[self.organization.slug, self.project.slug],
            ),
            "list_organization_user_reports": reverse(
                "api:list_organization_user_reports",
                args=[self.organization.slug, self.issue.id],
            ),
            "get_team": reverse(
                "api:get_team", args=[self.organization.slug, self.team.slug]
            ),
            "get_organization_member": reverse(
                "api:get_organization_member",
                args=[self.organization.slug, self.org_user.pk],
            ),
        }

    def test_scoped_route_query_shape(self):
        for label, url in self.urls().items():
            with self.subTest(route=label):
                self.assertEqual(
                    self.measure(url),
                    self.EXPECTED[label],
                    f"{label} query shape changed (total, auth_lookups, member_joins)",
                )

    def test_every_route_resolves_membership_exactly_once(self):
        """``resolve_org_auth`` is one query, and nothing caches it, so the
        count is also the count of permission checks. More than one means a
        view is re-deriving what ``OrgAuth`` already told it."""
        for label, url in self.urls().items():
            with self.subTest(route=label):
                _, auth_lookups, _ = self.measure(url)
                self.assertEqual(auth_lookups, 1)


class TokenCeilingEndToEndTestCase(TestCase):
    """A token is capped by its owner's role, and gated by their membership.

    ``resolve_org_auth`` intersects the token's scopes with the role's, so a
    token can only ever narrow what its owner could already do. These are the
    HTTP-level statements of that; the set arithmetic itself is covered in
    ``glitchtip/test_scope_resolution.py``.
    """

    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization")
        cls.owner = baker.make("users.user")
        cls.org.add_user(cls.owner, OrganizationUserRole.OWNER)
        cls.member = baker.make("users.user")
        cls.member_ou = cls.org.add_user(cls.member, OrganizationUserRole.MEMBER)
        cls.stranger = baker.make("users.user")

    def token(self, user, scopes):
        token = baker.make("api_tokens.APIToken", user=user)
        if scopes:
            token.add_permissions(scopes)
        return token

    def member_token(self, scopes):
        return self.token(self.member, scopes)

    def test_member_session_cannot_delete_organization(self):
        self.client.force_login(self.member)
        url = reverse("api:delete_organization", args=[self.org.slug])
        self.assertEqual(self.client.delete(url).status_code, 403)

    def test_member_token_cannot_delete_organization(self):
        """The regression the ceiling exists for: this used to return 204."""
        token = self.member_token(["org:admin", "org:write", "org:read"])
        url = reverse("api:delete_organization", args=[self.org.slug])
        res = self.client.delete(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 403, "a MEMBER token deleted the org")

    def test_member_token_cannot_remove_the_owner(self):
        """The other half: used to return 204."""
        token = self.member_token(["member:admin", "member:write", "member:read"])
        owner_ou = self.org.organization_users.get(user=self.owner)
        url = reverse(
            "api:delete_organization_member", args=[self.org.slug, owner_ou.pk]
        )
        res = self.client.delete(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 403, "a MEMBER token removed the OWNER")

    def test_owner_token_still_works(self):
        """The ceiling must not break the legitimate case."""
        token = self.token(self.owner, ["org:admin", "org:write", "org:read"])
        url = reverse("api:delete_organization", args=[self.org.slug])
        res = self.client.delete(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 204)

    def test_member_token_keeps_scopes_within_its_role(self):
        """The ceiling caps, it does not revoke."""
        token = self.member_token(["event:read", "org:admin"])
        url = reverse("api:list_issues", args=[self.org.slug])
        res = self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 200)

    def test_fully_scoped_token_of_a_non_member_is_refused(self):
        """Membership gates the token, not just its scopes.

        This is the case the old model let through the scope check -- token
        scopes were resolved without reference to any organization -- and only
        the separate org-id lookup kept the queryset narrow. It is now refused
        at the boundary.
        """
        token = self.token(self.stranger, list(SCOPES))
        url = reverse("api:list_issues", args=[self.org.slug])
        res = self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 403)

    def test_a_non_member_token_is_refused_on_a_specific_issue(self):
        """Same statement one level down, on a route that names an object.

        The refusal has to come from the decorator rather than from an empty
        queryset, otherwise removing a view's membership filter -- which is
        what the port does -- turns this into a leak.
        """
        their_issue = baker.make("issue_events.Issue")
        token = self.token(self.stranger, ["event:read", "event:admin"])
        for name, args in (
            (
                "api:get_organization_issue",
                [their_issue.project.organization.slug, their_issue.id],
            ),
            (
                "api:list_organization_comments",
                [their_issue.project.organization.slug, their_issue.id],
            ),
        ):
            with self.subTest(route=name):
                res = self.client.get(
                    reverse(name, args=args),
                    HTTP_AUTHORIZATION=f"Bearer {token.token}",
                )
                self.assertEqual(res.status_code, 403)
