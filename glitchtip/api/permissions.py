from functools import wraps

from ninja.errors import HttpError

from .authentication import AuthHttpRequest


def get_org_slug(kwargs: dict) -> str | None:
    return kwargs.get("organization_slug")


async def is_denied(request: AuthHttpRequest, permissions: list[str]) -> bool:
    """Whether the request's resolved scope fails to satisfy ``permissions``.

    "Any of" semantics, with a superuser bypass on the failure path only, so the
    extra user lookup never lands on a request that was going to succeed.

    The bypass is deliberately **session-only**: a token carries its own scopes,
    and a superuser who mints a narrowly-scoped token means that narrow scope.
    Note it clears this decorator but not the views themselves - their querysets
    filter on membership, so a non-member superuser trades a 403 for a 404.
    """
    if any(s in permissions for s in request.auth.scope):
        return False
    if request.auth.auth_type == "session" and await request.auth.is_superuser():
        return False
    return True


def has_permission(permissions: list[str]):
    """
    Check scoped permissions.

    Example: @has_permission(["event:write", "event:admin"])

    The decorated function requires at least one of the specified permissions.
    """

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            await request.auth.resolve_scope(get_org_slug(kwargs))
            if await is_denied(request, permissions):
                raise HttpError(403, "Permission denied")
            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator


def has_issue_permission(permissions: list[str]):
    """Scoped-permission check for the *bare* ``/issues/{id}/...`` routes.

    Unlike :func:`glitchtip.api.permissions.has_permission`, these routes carry
    no ``organization_slug`` in the path, so there is nothing for
    ``resolve_scope`` to scope a session user's permissions against. A user may
    belong to many organizations with different roles, so we resolve the *one*
    organization that owns the issue being accessed (issue -> project ->
    organization) and scope against that.

    Token auth carries its scopes on the token itself, independent of any
    organization, so we skip the extra lookup for tokens entirely.
    """

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            # Token scopes live on the token itself, independent of any
            # organization, so resolve_scope(None) checks them directly and we
            # skip the extra issue lookup entirely.
            if request.auth.auth_type != "token":
                issue_id = kwargs.get("issue_id")
                organization_slug: str | None = None
                if issue_id is not None:
                    # Local import avoids an import cycle at module load time.
                    from apps.issue_events.models import Issue

                    organization_slug = await (
                        Issue.objects.filter(id=issue_id)
                        .values_list("project__organization__slug", flat=True)
                        .afirst()
                    )
                if organization_slug is None:
                    # The issue does not exist in any organization (or the route
                    # carries no issue_id). There is nothing to authorize
                    # against and nothing to leak, so defer to the view, whose
                    # membership-scoped queryset raises 404.
                    return await f(request, *args, **kwargs)
                await request.auth.resolve_scope(organization_slug)
            else:
                await request.auth.resolve_scope(None)
            if await is_denied(request, permissions):
                raise HttpError(403, "Permission denied")
            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator
