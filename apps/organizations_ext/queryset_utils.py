from django.db.models import (
    Count,
    Exists,
    IntegerField,
    OuterRef,
    Prefetch,
    QuerySet,
    Subquery,
    Value,
)

from apps.projects.models import Project
from apps.teams.models import Team

from .models import Organization, OrganizationUser


def get_organization_for_user(
    user_id: int, organization_slug: str
) -> QuerySet[Organization]:
    """Get organization queryset filtered by user membership and slug."""
    return Organization.objects.filter(users=user_id, slug=organization_slug)


def get_organizations_queryset(
    org_id: int,
    user_id: int,
    role_required=False,
    add_details=False,
    actor_role=None,
):
    """One organization, which the caller is already known to belong to.

    Callers are behind ``@has_permission``, so ``org_id`` and ``actor_role``
    both come from the membership row it already read -- which is why there is
    no membership filter and no correlated subquery for the role here.
    ``user_id`` is only for the per-project and per-team payload annotations.

    For routes with no organization in the path, see
    :func:`get_user_organizations_queryset`.
    """
    qs = Organization.objects.filter(id=org_id, is_deleted=False)
    if role_required or add_details:
        qs = qs.annotate(actor_role=Value(actor_role, IntegerField()))
    if add_details:
        qs = _prefetch_organization_details(qs, user_id)
    return qs


def _prefetch_organization_details(
    qs: QuerySet[Organization], user_id: int
) -> QuerySet[Organization]:
    """Nested project and team payload for the detail schema.

    The joins to OrganizationUser here annotate per-team membership for
    display. They are payload, not authorization -- the schema reads them
    while rendering, so dropping them turns into lazy queries in an async
    view rather than into a smaller plan.
    """
    return qs.prefetch_related(
        Prefetch(
            "projects",
            queryset=Project.annotate_is_member(Project.objects, user_id),
        ),
        "projects__teams",
        Prefetch(
            "teams",
            queryset=Team.objects.annotate(
                is_member=Exists(
                    OrganizationUser.objects.filter(
                        teams=OuterRef("pk"), user_id=user_id
                    )
                ),
                member_count=Count("members"),
            ),
        ),
        "teams__members",
    )


def get_organization_users_queryset(
    org_id: int,
    user_id: int,
    team_slug: str | None = None,
    role_required=False,
    add_details=False,
    actor_role=None,
):
    """Members of one organization the caller is already known to belong to.

    As with :func:`get_organizations_queryset`, ``org_id`` and ``actor_role``
    come from the permission decorator, so neither the membership filter nor
    the role subquery is needed. The rows returned are other members -- that is
    the payload, not an authorization check.
    """
    qs = (
        OrganizationUser.objects.filter(organization_id=org_id)
        .select_related("user", "organization__owner")
        .prefetch_related("user__socialaccount_set")
    )
    if team_slug:
        qs = qs.filter(teams__slug=team_slug)
    if role_required:
        qs = qs.annotate(actor_role=Value(actor_role, IntegerField()))
    if add_details:
        qs = qs.prefetch_related("teams")
    return qs


def get_user_organizations_queryset(user_id: int, add_details=False):
    """Every organization the user belongs to.

    For routes with no organization in the path. The membership filter here IS
    the authorization -- do not "finish the port" by removing it.
    """
    qs = Organization.objects.filter(users=user_id, is_deleted=False)
    if add_details:
        # No decorator ran, so the role has to be read here rather than handed
        # over -- one subquery per organization row instead of a known value.
        qs = qs.annotate(
            actor_role=Subquery(
                OrganizationUser.objects.filter(
                    organization_id=OuterRef("pk"), user_id=user_id
                ).values("role")[:1]
            )
        )
        qs = _prefetch_organization_details(qs, user_id)
    return qs
