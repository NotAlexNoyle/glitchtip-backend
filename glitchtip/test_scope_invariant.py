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
  everything" -- that every org-scoped route carries one of the two gates in
  ``GATE_DECORATORS``, and that every ``actor_role=`` a caller passes is the
  int off the resolved ``OrgAuth``.
- ``CrossOrgIsolationTestCase`` walks every route family with a foreign
  organization slug and asserts it is refused -- 403 from ``has_permission``,
  an empty 200 from the folded gate -- and, for every route either way, that no
  foreign row comes back. Written against URLs rather than querysets on
  purpose, so it keeps working no matter which layer filters.
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
import inspect
import pathlib
import re

from asgiref.sync import async_to_sync, sync_to_async
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.db.models import IntegerField
from django.http import HttpRequest
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from model_bakery import baker

from apps.issue_events.models import Issue
from apps.organizations_ext.constants import OrganizationUserRole
from glitchtip.api import permissions
from glitchtip.api.authentication import Auth
from glitchtip.api.org_ids import aresolve_org_id
from glitchtip.api.permissions import (
    OrgAuth,
    OrgAuthError,
    org_scoped_qs,
    resolve_org_auth,
    scoped_org_id,
)
from glitchtip.api.scopes import SCOPES
from glitchtip.test_utils import generators  # noqa: F401
from glitchtip.test_utils.test_case import GlitchTestCase

ORGUSER_TABLE = "organizations_ext_organizationuser"
ORG_TABLE = "organizations_ext_organization"

BACKEND_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The decorators that gate an org-scoped route. Both are gates; they differ in
# what they leave behind.
#
# ``has_permission`` resolves an ``OrgAuth`` before the view body runs and
# raises 403 when the caller is not a member. The folded gates instead fold the
# membership test into the data query as an uncorrelated EXISTS: it costs no
# separate auth lookup, and it refuses by returning nothing rather than by
# raising. Only ``has_permission`` produces an ``OrgAuth``, so only it can
# satisfy ``scoped_org_id`` -- see the test below, which names it directly.
#
# The three folded variants differ only in which direction the queryset moves
# and what becomes of it, not in what they check. ``org_scoped_list`` and
# ``org_scoped_all`` take one out of the view and fold the gate into it on the
# way -- paginating it, or evaluating it whole. ``org_scoped_qs`` folds on the
# way IN instead, because a route that needs rows mid-body has nothing left to
# fold into by the time it returns; it hands the view an already-gated queryset
# as ``qs``. In every case the gate is in the decorator, so a gated route cannot
# be ungated -- see ``InjectedQuerysetIsTheGateTestCase``.
FOLDED_GATE_DECORATORS = frozenset(
    {"org_scoped_list", "org_scoped_all", "org_scoped_qs"}
)
GATE_DECORATORS = frozenset({"has_permission"}) | FOLDED_GATE_DECORATORS

# ``@org_scoped_qs`` routes that touch a manager directly *after* the gated
# queryset has already chosen the rows they may act on, and only ever keyed on
# ids that came back through it: ``update_issues`` writes through to the
# IssueIndex / IssueHash / IssueEvent leaves, ``issue_stats`` reads
# IssueAggregate rows for the issues the gate returned. The scope is inherited
# through those ids, so it is not re-applied.
#
# Anywhere else, a ``.objects`` in an injected route body is the view ignoring
# the queryset it was handed and building its own ungated one. Adding a name
# here is claiming the manager access is downstream of the gate -- check that
# the ids really did come from ``qs`` before you do.
INJECTED_ROUTES_WITH_FOLLOWUP_QUERIES = frozenset({"update_issues", "issue_stats"})

# The folded routes that resolve a single object, where "no rows" has to
# become a status code because there is no empty object to return. 404 is that
# code, so on these -- and only these -- a non-member is refused with 404 rather
# than with the 403 ``resolve_org_auth`` would have raised. The gate cannot tell
# "not a member" from "no such issue" (both are zero rows), and the message that
# distinguished them is gone with it. Deliberate, and revisitable: resolving the
# reason on the miss path alone would restore the 403 at the cost of a second
# query only when refusing. Until then this set is the record of where the
# status code stopped carrying the reason.
FOLDED_DETAIL_ROUTES = frozenset(
    {
        "get_organization_issue",
        "update_organization_issue",
        "delete_organization_issue",
        "list_organization_issue_tags",
        "list_organization_issue_commits",
    }
)

# The routes gated by one of ``FOLDED_GATE_DECORATORS``. Filtering *is* the
# refusal there, so a foreign organization gets an empty 200 instead of a 403,
# and the gate rides along on the data query instead of issuing its own. Both
# consequences are asserted below; this is the one place that lists the
# affected routes.
FOLDED_GATE_ROUTES = (
    frozenset(
        {
            "list_project_issues",
            "list_project_alerts",
            "list_issues",
            "issue_stats",
            "delete_issues",
            "update_issues",
        }
    )
    | FOLDED_DETAIL_ROUTES
)

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
        """

        class FakeRequest:
            auth = Auth(1, "session")

        with self.assertRaises(AttributeError):
            scoped_org_id(FakeRequest())


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
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "router"
            ):
                return True
            if isinstance(func, ast.Name) and any(
                isinstance(arg, ast.Name) and arg.id == "router" for arg in dec.args
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
        resolves it.

        ``has_permission`` by name, not ``GATE_DECORATORS``: ``scoped_org_id``
        reads ``request.org_auth``, and ``org_scoped_list`` never sets it. A
        folded-gate route that called ``scoped_org_id`` would raise
        ``AttributeError``, so it must not be excused here.
        """
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

    def test_injected_routes_take_the_queryset_they_are_handed(self):
        """``@org_scoped_qs`` gates the queryset it passes in, so the parameter
        it passes it through is not optional -- a route without one is a wiring
        mistake. The decorator refuses at import too; this states it where a
        reviewer reading the invariants will see it."""
        offenders = [
            f"{path}::{name}"
            for path, name, decorators, params, _source in self.routes()
            if "org_scoped_qs" in decorators and "qs" not in params
        ]
        self.assertEqual(
            offenders, [], "@org_scoped_qs route(s) declare no `qs` parameter"
        )

    def test_injected_routes_do_not_reach_past_the_gated_queryset(self):
        """The one failure injection leaves open: a view handed a gated queryset
        that ignores it and goes back to the manager for an ungated one.

        That is a ``.objects`` in a route body, which is greppable in a way the
        old "did you remember to call apply()" never was -- applying the scope
        to the wrong queryset looked identical to applying it to the right one.
        ``INJECTED_ROUTES_WITH_FOLLOWUP_QUERIES`` records where manager access
        is deliberate and why.
        """
        offenders = [
            f"{path}::{name}"
            for path, name, decorators, _params, source in self.routes()
            if "org_scoped_qs" in decorators
            and ".objects" in source
            and name not in INJECTED_ROUTES_WITH_FOLLOWUP_QUERIES
        ]
        self.assertEqual(
            offenders,
            [],
            "injected route(s) build their own queryset instead of using `qs`",
        )

    def test_org_scoped_routes_are_gated(self):
        """A ledger, not a wall.

        A route that takes an ``organization_slug`` is addressing one
        organization's data, so it should be gated -- by any decorator in
        ``GATE_DECORATORS``, since a folded gate is still a gate. The apps below
        are not ported yet -- they still carry their own membership filters.
        Shrink this list as they land; a *new* name appearing in the diff is the
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
            # auth=None -- an external monitor POSTs this with a secret in the
            # URL, so there is no session or token to resolve scopes from. This
            # one can never be gated.
            "apps/uptime/api.py::heartbeat_check",
        }
        ungated = {
            f"{path}::{name}"
            for path, name, decorators, params, _source in self.routes()
            if "organization_slug" in params
            and not GATE_DECORATORS.intersection(decorators)
        }
        self.assertEqual(
            ungated,
            expected_ungated,
            "an org-scoped route gained or lost its gate decorator",
        )

    def test_the_gate_decorators_all_exist(self):
        """``GATE_DECORATORS`` is matched against decorator names by string, so
        a renamed decorator would silently stop counting as a gate and quietly
        empty out the test above."""
        for name in GATE_DECORATORS:
            with self.subTest(decorator=name):
                self.assertTrue(
                    callable(getattr(permissions, name, None)),
                    f"{name} is in GATE_DECORATORS but is not a callable in "
                    "glitchtip.api.permissions",
                )

    def test_folded_gate_routes_use_the_folded_gate(self):
        """``FOLDED_GATE_ROUTES`` drives an empty-200 allowance and a query-count
        allowance further down. Pin it to the source so it cannot outlive the
        decorator it describes."""
        actual = {
            name
            for _path, name, decorators, _params, _source in self.routes()
            if FOLDED_GATE_DECORATORS.intersection(decorators)
        }
        self.assertEqual(
            actual,
            set(FOLDED_GATE_ROUTES),
            "a route gained or lost a folded gate without FOLDED_GATE_ROUTES "
            "being updated",
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

    A ``@has_permission`` route answers 403 and only 403. Under the old model a
    non-member fell through to a membership-scoped queryset and got 404, so
    "refused" meant "403 or 404"; ``resolve_org_auth`` refuses non-membership
    before the view runs, so that vaguer assertion no longer describes those
    routes.

    ``FOLDED_GATE_ROUTES`` are the exception, deliberately: ``org_scoped_list``
    expresses membership as a term in the data query rather than as a check that
    can raise, so a non-member is refused by receiving an empty 200. Isolation
    still holds -- no foreign row is ever served -- but the caller cannot tell
    "not yours" from "nothing here", so the status code stops carrying the
    refusal. See ``test_foreign_org_is_refused``.
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
            label: (reverse(name, args=args) + query, name.removeprefix("api:"))
            for label, (name, args, query) in routes.items()
        }

    def test_foreign_org_is_refused(self):
        """Refused, in whichever way the route's gate refuses.

        ``@has_permission`` raises before the view body runs, so the answer is
        403. A folded gate has no separate refusal to raise -- the membership
        test is a term in the data query -- so a non-member is refused by
        getting nothing back. On a collection that is an empty 200; on a route
        resolving a single object there is no empty object, so it is a 404. The
        three sets are ``FOLDED_DETAIL_ROUTES`` and ``FOLDED_GATE_ROUTES``,
        both pinned to the decorators in ``DecoratorIsTheBoundaryTestCase``.

        The empty body is not checked here; ``test_foreign_org_returns_no_rows``
        below already checks it for every route, folded-gate or not, and that is
        the assertion carrying the isolation guarantee for these two.
        """
        for label, (url, route) in self.foreign_urls().items():
            with self.subTest(route=label):
                res = self.client.get(url)
                if route in FOLDED_DETAIL_ROUTES:
                    self.assertEqual(
                        res.status_code,
                        404,
                        f"{label} resolves one object under a folded gate, so "
                        f"a foreign organization should get 404, not "
                        f"{res.status_code}. See FOLDED_DETAIL_ROUTES.",
                    )
                elif route in FOLDED_GATE_ROUTES:
                    self.assertEqual(
                        res.status_code,
                        200,
                        f"{label} is gated by a folded gate, which filters "
                        f"rather than raises, so a foreign organization should "
                        f"get an empty 200, not {res.status_code}. A 403 here "
                        "means the route moved to @has_permission -- drop it "
                        "from FOLDED_GATE_ROUTES.",
                    )
                else:
                    self.assertEqual(
                        res.status_code,
                        403,
                        f"{label} answered {res.status_code} for a foreign "
                        "organization; the decorator should have refused it",
                    )

    def test_foreign_org_returns_no_rows(self):
        """The property that actually carries cross-org isolation, and the only
        one the folded-gate routes have. Every route either refuses outright or
        hands over nothing."""
        for label, (url, _route) in self.foreign_urls().items():
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
    and any more is a view re-deriving what ``OrgAuth`` already handed it. A
    ``FOLDED_GATE_ROUTES`` route issues none, because ``org_scoped_list`` puts
    the check inside the data query; there the gate is counted as a
    ``member_join`` instead.
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
        "list_issues": (1, 0, 1),
        "list_organization_projects": (3, 1, 1),
        "list_teams": (3, 1, 2),
        "list_organization_members": (3, 1, 1),
        "get_project": (2, 1, 1),
        "list_project_keys": (2, 1, 0),
        "get_organization_issue": (1, 0, 1),
        "list_organization_issue_event": (2, 1, 0),
        "list_project_issues": (1, 0, 1),
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
        # These numbers are the steady state, which is what production runs
        # in: the slug -> org id map is a per-worker cache warmed by the first
        # request naming a slug. The test runner clears it before every test,
        # so warm it here rather than measuring one cold probe that no real
        # request after the first would pay. Without this the folded-gate
        # routes read as one auth lookup instead of zero.
        async_to_sync(aresolve_org_id)(self.organization.slug)

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
        count is also the count of permission checks. More than one means a view
        is re-deriving what ``OrgAuth`` already told it.

        A ``FOLDED_GATE_ROUTES`` route resolves membership exactly once too --
        it just does it inside the data query, as an EXISTS on a table the data
        query was already touching, so it shows up as zero *separate* lookups
        and one membership join. Zero is the point of that decorator; what is
        forbidden either way is a second check.
        """
        for label, url in self.urls().items():
            with self.subTest(route=label):
                _, auth_lookups, member_joins = self.measure(url)
                if label in FOLDED_GATE_ROUTES:
                    self.assertEqual(
                        auth_lookups,
                        0,
                        f"{label} is gated by a folded gate, whose whole "
                        "purpose is to fold the check into the data query; a "
                        "separate auth lookup means it is being resolved twice",
                    )
                    self.assertGreaterEqual(
                        member_joins,
                        1,
                        f"{label} shows no membership table in its data query, "
                        "so the folded gate is not there -- the route is "
                        "returning rows with nothing checking membership",
                    )
                else:
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
        # A visible row, so a 200 on a folded-gate route means "the gate passed"
        # rather than "the gate refused me quietly" -- the two are the same
        # status code there, and an empty fixture cannot tell them apart.
        cls.project = baker.make("projects.Project", organization=cls.org)
        cls.issue = baker.make("issue_events.Issue", project=cls.project)

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
        """The ceiling caps, it does not revoke.

        ``list_issues`` is folded, so 200 alone would also be how it refuses.
        The row is the assertion that carries the meaning here.
        """
        token = self.member_token(["event:read", "org:admin"])
        url = reverse("api:list_issues", args=[self.org.slug])
        res = self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(
            [row["id"] for row in res.json()],
            [str(self.issue.id)],
            "event:read survived the ceiling, so the issue should be visible",
        )

    def test_fully_scoped_token_of_a_non_member_is_refused(self):
        """Membership gates the token, not just its scopes.

        This is the case the old model let through the scope check -- token
        scopes were resolved without reference to any organization -- and only
        the separate org-id lookup kept the queryset narrow. It is now refused
        at the boundary.
        """
        token = self.token(self.stranger, list(SCOPES))
        url = reverse("api:list_organization_members", args=[self.org.slug])
        res = self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 403)

    def test_fully_scoped_token_of_a_non_member_gets_nothing_when_folded(self):
        """The same statement on a folded gate, which cannot raise.

        A stranger holding every scope in the system still sees no rows,
        because the EXISTS in the data query is the membership test. The status
        code stops carrying the refusal, so the body has to.
        """
        token = self.token(self.stranger, list(SCOPES))
        url = reverse("api:list_issues", args=[self.org.slug])
        res = self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), [], "a non-member token saw issues")

    def test_a_non_member_token_is_refused_on_a_specific_issue(self):
        """Same statement one level down, on routes that name an object.

        What must hold is that the row is never served. Which code says so
        depends on the gate: ``list_organization_comments`` is still
        ``@has_permission`` and refuses with 403, while
        ``get_organization_issue`` is folded and refuses with 404 -- see
        ``FOLDED_DETAIL_ROUTES``. Both are refusals; neither returns the issue.
        """
        their_issue = baker.make("issue_events.Issue")
        token = self.token(self.stranger, ["event:read", "event:admin"])
        for name, args, expected in (
            (
                "api:get_organization_issue",
                [their_issue.project.organization.slug, their_issue.id],
                404,
            ),
            (
                "api:list_organization_comments",
                [their_issue.project.organization.slug, their_issue.id],
                403,
            ),
        ):
            with self.subTest(route=name):
                res = self.client.get(
                    reverse(name, args=args),
                    HTTP_AUTHORIZATION=f"Bearer {token.token}",
                )
                self.assertEqual(res.status_code, expected)


async def _ungated_source(request, **kwargs):
    """The base queryset a route declares. Nothing here authorizes anything."""
    return Issue.objects.all()


@org_scoped_qs(["event:read", "event:write", "event:admin"], _ungated_source)
async def _injected_view(request, qs, organization_slug: str):
    return [issue async for issue in qs]


class InjectedQuerysetIsTheGateTestCase(TestCase):
    """``@org_scoped_qs`` gates by handing the view an already-gated queryset.

    Its predecessor ``@org_scoped`` built the scope and asked the view to call
    ``request.org_scope.apply()`` on the right queryset, then checked afterwards
    that *something* had been applied. That could only ever be a tripwire: it
    caught the gate being dropped entirely, not the gate being applied to a
    queryset the response did not come from.

    Folding on the way in removes the question. The base queryset below is
    deliberately ``Issue.objects.all()`` -- wide open, no membership filter, no
    organization filter -- so anything these tests do not see is the decorator's
    doing and nothing else.
    """

    @classmethod
    def setUpTestData(cls):
        cls.mine = make_org_fixture()
        cls.theirs = make_org_fixture()

    def request_for(self, fixture):
        request = HttpRequest()
        request.auth = Auth(fixture["user"].id, "session")
        return request

    async def test_the_view_receives_a_gated_queryset(self):
        rows = await _injected_view(
            self.request_for(self.mine), organization_slug=self.mine["org"].slug
        )
        self.assertEqual([i.id for i in rows], [self.mine["issue"].id])

    async def test_a_foreign_org_reaches_nothing(self):
        rows = await _injected_view(
            self.request_for(self.mine), organization_slug=self.theirs["org"].slug
        )
        self.assertEqual(rows, [])

    def test_a_view_without_a_qs_parameter_is_refused_at_decoration(self):
        """The gate has nowhere to put the queryset, so this cannot be wired up
        wrong quietly -- it fails at import, before the route is ever served."""
        with self.assertRaises(ImproperlyConfigured) as caught:

            @org_scoped_qs(["event:read"], _ungated_source)
            async def _no_qs(request, organization_slug: str):  # pragma: no cover
                return []

        self.assertIn("takes no `qs`", str(caught.exception))

    def test_qs_is_hidden_from_the_signature_ninja_reads(self):
        """``qs`` is supplied by the decorator, so ninja must not see it and try
        to bind it as a query parameter. ``@wraps`` leaves a ``__wrapped__``
        that ``inspect.signature`` follows back to the undecorated view, so this
        only holds while the decorator sets ``__signature__`` itself."""
        params = list(inspect.signature(_injected_view).parameters)
        self.assertEqual(params, ["request", "organization_slug"])


class FoldedGateMutationsAreNoOpsTestCase(GlitchTestCase):
    """A folded gate on a *mutation* refuses by changing nothing.

    ``CrossOrgIsolationTestCase`` walks GET routes, so it cannot reach these
    two. They are the uncomfortable case for the folded gate: a non-member gets
    200 and a success-shaped body from a bulk delete, which reads as "done".
    Nothing was done, and that is the only thing making the empty-200 refusal
    acceptable here, so it is asserted rather than assumed.
    """

    @classmethod
    def setUpTestData(cls):
        cls.mine = make_org_fixture()
        cls.theirs = make_org_fixture()
        cls.user = cls.mine["user"]

    def setUp(self):
        self.client.force_login(self.user)

    def foreign_issue(self):
        return Issue.objects.get(id=self.theirs["issue"].id)

    def test_a_foreign_bulk_delete_deletes_nothing(self):
        url = reverse("api:delete_issues", args=[self.theirs["org"].slug])
        res = self.client.delete(url + "?id=" + str(self.theirs["issue"].id))
        self.assertEqual(res.status_code, 200)
        self.assertFalse(
            self.foreign_issue().is_deleted,
            "a non-member's bulk delete reached another organization's issue",
        )

    def test_a_foreign_bulk_update_updates_nothing(self):
        url = reverse("api:update_issues", args=[self.theirs["org"].slug])
        before = self.foreign_issue().index.status
        res = self.client.put(
            url + "?id=" + str(self.theirs["issue"].id),
            data={"status": "resolved"},
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(
            self.foreign_issue().index.status,
            before,
            "a non-member's bulk update changed another organization's issue",
        )

    def test_the_same_calls_work_inside_my_own_organization(self):
        """Guard against the two above passing because the routes are broken."""
        mine = self.mine["issue"]
        url = reverse("api:delete_issues", args=[self.mine["org"].slug])
        res = self.client.delete(url + "?id=" + str(mine.id))
        self.assertEqual(res.status_code, 200)
        # The route flags the issue and enqueues the reaper, which runs inline
        # under the test task backend, so the row is gone rather than flagged.
        self.assertFalse(
            Issue.objects.filter(id=mine.id).exists(),
            "the same call inside my own organization did nothing either, so "
            "the two tests above prove nothing",
        )
