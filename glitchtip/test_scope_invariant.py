"""Safety net for the ORM-aware scoping port.

The port deletes the membership filters that views currently carry, on the
grounds that ``@has_permission`` already proved membership before the view ran.
That is only safe if the decorator really is the boundary, so these tests pin
the boundary itself:

- ``CrossOrgIsolationTestCase`` walks every route family with a foreign
  organization slug and asserts the caller is refused. It is written against
  URLs rather than querysets on purpose, so it keeps passing (or starts
  failing) no matter which layer does the filtering.
- ``ScopeInvariantTestCase`` states the invariant the port rests on: if
  ``@has_permission`` let the request through, an organization was resolved and
  the actor is a member of it.
- ``ScopedQueryCountTestCase`` locks in the query counts the port is for, so a
  later change cannot quietly reintroduce a round trip.
- ``TokenCeilingEndToEndTestCase`` and ``ForeignIssueRefusalTestCase`` are the
  HTTP-level versions of the two token fixes the port depended on, kept
  separately from the Auth-level tests in
  ``apps/organizations_ext/tests/test_scope_resolution.py`` because it is the
  status code a caller receives that matters here.
"""

import re

from asgiref.sync import sync_to_async
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from model_bakery import baker

from apps.organizations_ext.constants import OrganizationUserRole
from glitchtip.api.authentication import Auth, ScopeNotResolved
from glitchtip.api.permissions import scoped_org_id
from glitchtip.test_utils import generators  # noqa: F401
from glitchtip.test_utils.test_case import GlitchTestCase

ORGUSER_TABLE = "organizations_ext_organizationuser"
ORG_TABLE = "organizations_ext_organization"


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
        'org': org,
        'user': user,
        'org_user': org_user,
        'project': project,
        'team': team,
        'issue': issue,
        'release': release,
        'environment': environment }


class CrossOrgIsolationTestCase(GlitchTestCase):
    """A member of one organization must not reach another's resources.

    Both organizations are fully populated, so a route that leaks would return
    a real object rather than an empty list -- an empty-fixture foreign org
    would pass these tests even with the filtering removed.
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

    def test_foreign_org_is_refused(self):
        for label, url in self.foreign_urls().items():
            with self.subTest(route=label):
                res = self.client.get(url)
                self.assertIn(
                    res.status_code,
                    (403, 404),
                    f"{label} leaked a foreign organization ({res.status_code})",
                )

    def test_foreign_org_returns_no_rows(self):
        """A 200 with an empty list is still a leak of the org's existence, but
        a 200 with *rows* is a leak of its data. Assert the stronger property
        wherever a route answers at all."""
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


class ScopeInvariantTestCase(TestCase):
    """The invariant the port rests on.

    Every view that drops its membership filter relies on this: if
    ``@has_permission`` did not raise, ``scoped_org_id()`` returns an
    organization the actor belongs to. Break it and the ported querysets stop
    being scoped at all.
    """

    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization")
        cls.org.add_user(baker.make("users.user"), OrganizationUserRole.OWNER)
        cls.member = baker.make("users.user")
        cls.org.add_user(cls.member, OrganizationUserRole.MEMBER)
        cls.stranger = baker.make("users.user")

    async def test_member_resolves_own_org(self):
        auth = Auth(self.member.id, "session")
        await auth.resolve_scope(self.org.slug)
        self.assertEqual(auth.org_id, self.org.id)

    async def test_non_member_resolves_nothing_and_has_no_scope(self):
        """The two halves together are the invariant: no scope means
        ``has_permission`` raises, and no org id means a view that ran anyway
        cannot widen its queryset."""
        auth = Auth(self.stranger.id, "session")
        self.assertEqual(await auth.resolve_scope(self.org.slug), set())
        with self.assertRaises(ScopeNotResolved):
            _ = auth.org_id

    async def test_non_member_token_resolves_no_org(self):
        """A token supplies its own scopes, so it can clear the scope check on
        an org it does not belong to. Membership still gates the org id, which
        is what keeps a ported queryset from widening."""
        token = await baker.amake("api_tokens.APIToken", user=self.stranger)
        auth = Auth(self.stranger.id, "token", data=token)
        await auth.resolve_scope(self.org.slug)
        with self.assertRaises(ScopeNotResolved):
            _ = auth.org_id

    def test_unresolved_request_raises_rather_than_returning_none(self):
        """A view that forgot its decorator must 500, not serve everything."""

        class FakeRequest:
            auth = Auth(1, "session")

        with self.assertRaises(ScopeNotResolved):
            scoped_org_id(FakeRequest())


class ScopedQueryCountTestCase(GlitchTestCase):
    """Locks in what the port bought, so it cannot be undone by accident.

    Two costs are tracked separately. ``auth_lookups`` counts queries that only
    touch the organization tables -- the permission decorator issues exactly
    one, and any more is a view re-deriving what it was already handed.
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
        # Measured before the port, same classifier, for comparison:
        #   get_organization_issue         3 queries (2 auth lookups), 1 join
        #   list_organization_issue_event  3 queries (2 auth lookups), 0 joins
        #   list_project_issues            3 queries (2 auth lookups), 1 join
        #   list_organization_user_reports 2 queries (1 auth lookup),  1 join
        #   list_project_keys              2 queries (1 auth lookup),  1 join
        #   get_team                       3 queries (1 auth lookup),  2 joins
        #   get_organization_member        4 queries (1 auth lookup),  1 join
        # The first three each dropped a whole round trip; the next two dropped
        # a membership join. get_team and get_organization_member are unchanged
        # on purpose -- their joins are the team member list and the member rows
        # themselves, which are the response body.
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

    def test_scoped_route_query_shape(self):
        urls = {
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
        for label, url in urls.items():
            with self.subTest(route=label):
                self.assertEqual(
                    self.measure(url),
                    self.EXPECTED[label],
                    f"{label} query shape changed (total, auth_lookups, member_joins)",
                )

    def test_decorator_issues_exactly_one_auth_lookup(self):
        """Whatever else a route does, it should resolve membership once."""
        url = reverse("api:list_issues", args=[self.organization.slug])
        _, auth_lookups, _ = self.measure(url)
        self.assertEqual(auth_lookups, 1)


class TokenCeilingEndToEndTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = baker.make("organizations_ext.Organization")
        cls.owner = baker.make("users.user")
        cls.org.add_user(cls.owner, OrganizationUserRole.OWNER)
        cls.member = baker.make("users.user")
        cls.member_ou = cls.org.add_user(cls.member, OrganizationUserRole.MEMBER)

    def member_token(self, scopes):
        token = baker.make("api_tokens.APIToken", user=self.member)
        token.add_permissions(scopes)
        return token

    def test_member_session_cannot_delete_organization(self):
        self.client.force_login(self.member)
        url = reverse("api:delete_organization", args=[self.org.slug])
        self.assertEqual(self.client.delete(url).status_code, 403)

    def test_member_token_cannot_delete_organization(self):
        """The regression: this used to return 204."""
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
        token = baker.make("api_tokens.APIToken", user=self.owner)
        token.add_permissions(["org:admin", "org:write", "org:read"])
        url = reverse("api:delete_organization", args=[self.org.slug])
        res = self.client.delete(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 204)

    def test_member_token_keeps_scopes_within_its_role(self):
        """The ceiling caps, it does not revoke."""
        token = self.member_token(["event:read", "org:admin"])
        url = reverse("api:list_issues", args=[self.org.slug])
        res = self.client.get(url, HTTP_AUTHORIZATION=f"Bearer {token.token}")
        self.assertEqual(res.status_code, 200)


class ForeignIssueRefusalTestCase(TestCase):
    """A non-member token on someone else's issue is refused by the decorator."""

    @classmethod
    def setUpTestData(cls):
        cls.stranger = baker.make("users.user")
        cls.their_issue = baker.make("issue_events.Issue")

    async def test_non_member_token_is_forbidden_not_notfound(self):
        token = await baker.amake("api_tokens.APIToken", user=self.stranger)
        await sync_to_async(token.add_permissions)(["event:read"])
        url = reverse("api:get_issue", kwargs={"issue_id": self.their_issue.id})
        res = await self.async_client.get(
            url, headers={"authorization": f"Bearer {token.token}"}
        )
        self.assertEqual(res.status_code, 403)

    async def test_comments_on_a_foreign_issue_are_refused(self):
        """The route whose queryset filter this port removed."""
        token = await baker.amake("api_tokens.APIToken", user=self.stranger)
        await sync_to_async(token.add_permissions)(["event:read", "event:admin"])
        url = reverse("api:list_comments", kwargs={"issue_id": self.their_issue.id})
        res = await self.async_client.get(
            url, headers={"authorization": f"Bearer {token.token}"}
        )
        self.assertEqual(res.status_code, 403)
