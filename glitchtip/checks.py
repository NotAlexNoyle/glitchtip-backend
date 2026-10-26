"""Startup validation for the folded gate's model registry and route scopes.

These checks run on ``manage.py check``, ``runserver``, ``migrate``, and in
the test runner, so an ``org_field`` that does not reach the organization
foreign key fails at startup rather than in a request on a gated route.
"""

from collections.abc import Iterator

from django.core.checks import Error, Tags, register
from django.core.exceptions import FieldError
from django.db.models import Model
from django.db.models.constants import LOOKUP_SEP
from django.db.models.sql.datastructures import MultiJoin
from django.db.models.sql.query import Query

from apps.organizations_ext.models import Organization

from .base_models import ORG_SCOPED_MODELS


def registered_models(app_configs) -> Iterator[type[Model]]:
    """The registered models that have a table to isolate.

    The mixin appends every subclass it sees, including abstract bases, which
    have no table of their own -- their concrete children register separately
    and are checked on their own.
    """
    labels = None if app_configs is None else {config.label for config in app_configs}
    for model in ORG_SCOPED_MODELS:
        if not (isinstance(model, type) and issubclass(model, Model)):
            continue
        if model._meta.abstract:
            continue
        if labels is None or model._meta.app_label in labels:
            yield model


def check_org_field(model: type[Model]) -> Error | None:
    """Resolve ``model.org_field`` and confirm it lands on the organization FK.

    ``OrgScope.apply`` filters this path against an organization id. A path
    that stops anywhere else either fails to compile or -- worse -- compiles
    into a filter that isolates nothing.
    """
    try:
        _, final_field, _, _ = Query(model).names_to_path(
            model.org_field.split(LOOKUP_SEP),
            model._meta,
            allow_many=False,
            fail_on_missing=True,
        )
    except MultiJoin:
        return Error(
            f"{model._meta.label}.org_field is {model.org_field!r}, which crosses a "
            "multi-valued relation rather than following foreign keys. The gate "
            "would duplicate rows and admit a row whenever any related row is in "
            "the organization, which isolates nothing.",
            hint="Every segment of org_field must be a forward foreign key.",
            obj=model,
            id="glitchtip.E003",
        )
    except FieldError as err:
        return Error(
            f"{model._meta.label}.org_field is {model.org_field!r}, which does "
            f"not resolve on this model: {err}",
            hint="org_field is an ORM path, so every segment must be a field "
            "or relation reachable from this model.",
            obj=model,
            id="glitchtip.E001",
        )

    if model is Organization and final_field.primary_key:
        # The organization itself is gated on its own id.
        return None
    if not (final_field.is_relation and final_field.related_model is Organization):
        return Error(
            f"{model._meta.label}.org_field is {model.org_field!r}, which ends "
            f"at {final_field!r} rather than the organization foreign key, so "
            "the folded gate cannot isolate this model by organization.",
            hint="End the path on the foreign key column itself, such as "
            "'organization_id' or 'project__organization_id'. A path reaching "
            "past it onto a column of organization joins that table.",
            obj=model,
            id="glitchtip.E002",
        )
    return None


def check_undeleted_through(model: type[Model]) -> Error | None:
    """Confirm each ``undeleted_through`` path reaches a soft-deletable parent.

    ``OrgScope.apply`` filters ``<path>__is_deleted``, so a typo would fail on
    the first gated request instead of here.
    """
    for path in model.undeleted_through:
        try:
            Query(model).names_to_path(
                [*path.split(LOOKUP_SEP), "is_deleted"],
                model._meta,
                allow_many=False,
                fail_on_missing=True,
            )
        except (FieldError, MultiJoin) as err:
            return Error(
                f"{model._meta.label}.undeleted_through has {path!r}, which is "
                f"not a forward foreign key path to a soft-deletable model: {err}",
                hint="Each path must follow forward foreign keys to a model "
                "with an is_deleted field, such as 'project'.",
                obj=model,
                id="glitchtip.E004",
            )
    return None


@register(Tags.models)
def check_org_scoped_models(app_configs, **kwargs) -> list[Error]:
    return [
        error
        for model in registered_models(app_configs)
        for check in (check_org_field, check_undeleted_through)
        if (error := check(model))
    ]


def check_scope_levels(label: str, methods, scopes, view) -> list[Error]:
    """A read names only :read scopes, and a write admitting X:write admits X:admin.

    Tokens get no hierarchy: a scope counts only where a route lists it.
    """
    errors = []
    higher = sorted(s for s in scopes if s.endswith((":write", ":admin")))
    if "GET" in methods and higher:
        errors.append(
            Error(
                f"{label} is a read but admits {higher}, so a token without "
                "the matching :read scope can read it.",
                hint="A read route lists only :read scopes.",
                obj=view,
                id="glitchtip.E005",
            )
        )
    for scope in sorted(scopes):
        family, _, level = scope.partition(":")
        if level == "write" and f"{family}:admin" not in scopes:
            errors.append(
                Error(
                    f"{label} admits {scope} but not {family}:admin, so a "
                    "token holding only the admin scope is refused.",
                    hint=f"List {family}:admin beside {scope}.",
                    obj=view,
                    id="glitchtip.E006",
                )
            )
    return errors


def route_scope_errors(routers, app_configs=None) -> list[Error]:
    """Check the scope lists ``org_scoped`` and ``has_permission`` leave on views."""
    modules = None if app_configs is None else tuple(c.name for c in app_configs)
    errors = []
    seen = set()
    for prefix, router in routers:
        for path, path_view in router.path_operations.items():
            for operation in path_view.operations:
                view = operation.view_func
                # optional_slash registers one view under two paths.
                key = (view, tuple(operation.methods))
                if key in seen:
                    continue
                seen.add(key)
                if modules is not None and not view.__module__.startswith(modules):
                    continue
                route = f"{prefix}/{path.lstrip('/')}"
                label = f"{'/'.join(operation.methods)} {route}"
                for scopes in (
                    getattr(view, "gate_scopes", None),
                    getattr(view, "token_scopes", None),
                ):
                    if scopes:
                        errors += check_scope_levels(
                            label, operation.methods, scopes, view
                        )
    return errors


@register(Tags.urls)
def check_route_scopes(app_configs, **kwargs) -> list[Error]:
    # The API imports every app's routes, so it can only load once apps are ready.
    from .api.api import api

    return route_scope_errors(api._routers, app_configs)
