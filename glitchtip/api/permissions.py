from functools import wraps

from ninja.errors import HttpError

from .authentication import AuthHttpRequest

def get_org_slug(kwargs: dict) -> str | None:
    return kwargs.get("organization_slug")


def has_permission(permissions: list[str]):
    """
    Check scoped permissions.

    Example: @has_permission(["event:write", "event:admin"])

    The decorated function requires at least one of the specified permissions.
    """

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: AuthHttpRequest, *args, **kwargs):
            scopes = await request.auth.resolve_scope(get_org_slug(kwargs))
            if not any(s in permissions for s in scopes):
                raise HttpError(403, "Permission denied")
            return await f(request, *args, **kwargs)

        return decorated_function

    return decorator
