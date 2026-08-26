"""The scope registry is frozen: no more, no less, and never reordered.

``glitchtip/api/scopes.py`` looks like a plain list of strings. It is not. It
is a wire format with two consumers that disagree about what a scope *is*:

- ``SCOPES`` (the tuple) is fed to ``BitField(flags=SCOPES)`` on
  ``APIToken.scopes``. In ``bitfield/models.py`` a flag's value is its
  **index** in that tuple, and the column is an opaque bigint. Reordering,
  inserting, or removing an entry silently re-maps every integer already
  stored against every existing token -- a token that read events yesterday
  administers members today. Django notices nothing: the generated
  ``AlterField`` emits no DDL, because the column type never changed.
- ``Scopes`` (the ``Literal``) is the type every other consumer reads --
  ``OrgAuth.scope``, ``ROLES``, and ``OrganizationDetailSchema.access``, whose
  order is reproduced verbatim in the generated frontend contract. It is a
  hand-maintained twin of the tuple with nothing tying the two together.

So the registry has no safe edit except an append, and even an append should be
a decision somebody made on purpose rather than a line that arrived with a
feature. This module is the friction: the expected values below are
hand-written LITERALS, so *any* change to the registry fails here until a human
edits this file too.

Nothing here may be derived from ``glitchtip.api.scopes``. Deriving would let a
reorder move the actual and the expected together and pass green while
corrupting data -- the same reason
``apps/api_tokens/tests.py::ScopeBitStabilityTests`` hardcodes its bit map.
That test pins decoding (mask in, scope set out); this one pins the registry
those bits are read from, and every duplicate of it in the tree.
"""

import ast
import pathlib
from itertools import pairwise
from typing import get_args

from django.test import SimpleTestCase

from apps.api_tokens.models import APIToken
from apps.oauth.provider import DEFAULT_SCOPES, VALID_SCOPES
from apps.organizations_ext.constants import ROLES
from apps.projects.management.commands.bootstrap_dev import ALL_SCOPES
from bitfield.models import MAX_FLAG_COUNT
from glitchtip.api.scopes import SCOPES, Scopes

BACKEND_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The registry, frozen. The comments are the bit position each flag occupies in
# APIToken.scopes -- why the ORDER of this tuple is load-bearing and not merely
# tidy.
PINNED_SCOPES = (
    "project:read",  # bit 0
    "project:write",  # bit 1
    "project:admin",  # bit 2
    "project:releases",  # bit 3
    "team:read",  # bit 4
    "team:write",  # bit 5
    "team:admin",  # bit 6
    "event:read",  # bit 7
    "event:write",  # bit 8
    "event:admin",  # bit 9
    "org:read",  # bit 10
    "org:write",  # bit 11
    "org:admin",  # bit 12
    "member:read",  # bit 13
    "member:write",  # bit 14
    "member:admin",  # bit 15
    "org:integrations",  # bit 16
)

PINNED_SCOPE_COUNT = 17

# Migrations only ever appended, so every historical flag tuple is a prefix of
# the registry. This 16-flag prefix is the state real tokens were written
# against, before `org:integrations`.
PINNED_LEGACY_SCOPES = PINNED_SCOPES[:16]


def _source_modules():
    """Every non-test, non-migration module under ``apps/`` and ``glitchtip/``."""
    for root in ("apps", "glitchtip"):
        for path in sorted(BACKEND_ROOT.glob(f"{root}/**/*.py")):
            if "migrations" in path.parts or "tests" in path.parts:
                continue
            if path.name.startswith("test_") or path.name == "tests.py":
                continue
            yield path


class ScopeRegistryTestCase(SimpleTestCase):
    """``SCOPES`` and ``Scopes`` are one registry that happens to be typed twice."""

    def test_scopes_tuple_is_exactly_the_pinned_registry(self):
        """Tuple equality, so this fails on an addition, a removal, OR a swap.

        If you are here because you appended a scope: confirm it went on the
        END, update the literals in this file, and check the other copies the
        cases below pin.
        """
        self.assertEqual(SCOPES, PINNED_SCOPES)

    def test_scope_count_is_pinned(self):
        """Stated separately so a bare add or remove says so in the failure."""
        self.assertEqual(len(SCOPES), PINNED_SCOPE_COUNT)

    def test_registry_is_immutable(self):
        """A list would let anything holding the module mutate flag positions at
        runtime, after ``BitField`` captured the reference."""
        self.assertIsInstance(SCOPES, tuple)

    def test_registry_has_no_duplicates(self):
        """``BitFieldFlags.__getattr__`` resolves a name with ``.index()``, so a
        repeated name is unreachable at its own bit and can never be set."""
        self.assertEqual(len(set(SCOPES)), len(SCOPES))

    def test_registry_fits_the_bitfield_ceiling(self):
        """Flags are bits in a bigint; there are only 63 of them."""
        self.assertLessEqual(PINNED_SCOPE_COUNT, MAX_FLAG_COUNT)

    def test_scopes_literal_matches_the_tuple_exactly(self):
        """The type and the bitfield must name the same scopes in the same order.
        An entry in one and not the other is either a scope no token can hold or
        a scope no signature will accept."""
        self.assertEqual(get_args(Scopes), PINNED_SCOPES)

    def test_token_field_carries_the_registry_in_order(self):
        """Pins the live ``BitField`` on the model, not only the module constant
        it was built from."""
        self.assertEqual(tuple(APIToken.scopes.keys()), PINNED_SCOPES)


class MigrationHistoryTestCase(SimpleTestCase):
    """The recorded migration state is a third copy of the registry.

    ``makemigrations`` will happily write a reordered tuple into a new migration
    and call the model consistent again, so a mismatch here is the only signal
    that the reorder happened. Read from the migration files with ``ast`` rather
    than the migration loader: the loader needs the whole graph, and this repo's
    graph has dangling nodes left by earlier squashes.
    """

    @staticmethod
    def _bitfield_flag_tuples(path: pathlib.Path) -> list[tuple[str, ...]]:
        """Every ``BitField((...))`` flag tuple written in one migration."""
        found = []
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", "")
            )
            if name != "BitField":
                continue
            flags = node.args[0]
            if isinstance(flags, (ast.Tuple, ast.List)):
                found.append(
                    tuple(
                        e.value
                        for e in flags.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    )
                )
        return found

    @classmethod
    def recorded_flags(cls) -> list[tuple[str, tuple[str, ...]]]:
        migrations = BACKEND_ROOT / "apps" / "api_tokens" / "migrations"
        return [
            (path.name, flags)
            for path in sorted(migrations.glob("0*.py"))
            for flags in cls._bitfield_flag_tuples(path)
        ]

    def test_a_migration_records_the_scopes_field(self):
        """Guard the guard: an empty sweep would make the rest vacuously pass."""
        self.assertTrue(
            self.recorded_flags(), "no BitField found in the api_tokens migrations"
        )

    def test_latest_recorded_state_is_the_pinned_registry(self):
        name, flags = self.recorded_flags()[-1]
        self.assertEqual(flags, PINNED_SCOPES, f"{name} disagrees with the registry")

    def test_recorded_history_is_append_only(self):
        """Every historical tuple is a prefix of the registry. A reorder shows up
        here as a prefix that stopped being one."""
        for name, flags in self.recorded_flags():
            with self.subTest(migration=name):
                self.assertEqual(flags, PINNED_SCOPES[: len(flags)])

    def test_the_earliest_recorded_state_is_the_legacy_prefix(self):
        """The 16-flag state tokens in the wild were written against."""
        _name, first = self.recorded_flags()[0]
        self.assertEqual(first, PINNED_LEGACY_SCOPES)


class RoleScopesTestCase(SimpleTestCase):
    """``ROLES`` is what a session user actually gets, and it is written by hand.

    A role naming a scope outside the registry is a grant of nothing: it can
    never appear on a token and never satisfy a decorator. A registry entry no
    role grants is the mirror image -- a scope that gates a route nobody can
    reach.
    """

    def test_every_role_scope_is_registered(self):
        for role in ROLES:
            unknown = sorted(set(role["scopes"]) - set(PINNED_SCOPES))
            with self.subTest(role=role["id"]):
                self.assertEqual(
                    unknown, [], f"{role['id']} grants unregistered scope(s)"
                )

    def test_owner_grants_the_whole_registry(self):
        """Owner is unrestricted by definition, so it is also the proof that no
        registry entry is unreachable. A deliberately owner-less scope has to
        change this assertion on the way in."""
        owner = next(role for role in ROLES if role["id"] == "owner")
        self.assertEqual(set(owner["scopes"]), set(PINNED_SCOPES))

    def test_roles_only_widen(self):
        """member < admin < manager < owner, positionally -- the order
        ``OrganizationUserRole`` indexes into. What makes gating a route on the
        narrowest sufficient scope safe."""
        for lower, higher in pairwise(ROLES):
            with self.subTest(lower=lower["id"], higher=higher["id"]):
                self.assertLessEqual(set(lower["scopes"]), set(higher["scopes"]))


class DecoratorScopesTestCase(SimpleTestCase):
    """``@has_permission`` takes ``list[str]``, not ``list[Scopes]``.

    Nothing checks its arguments, at import time or at call time. A typo'd scope
    becomes a frozenset that intersects nothing, so the route denies every
    caller including the owner, with a 403 that reads exactly like a real
    permission failure. This is the check that catches it.
    """

    @staticmethod
    def _literal_scopes(call: ast.Call) -> list[str] | None:
        """The scope strings, or ``None`` if the argument is not a plain literal."""
        if len(call.args) != 1 or not isinstance(call.args[0], ast.List):
            return None
        elts = call.args[0].elts
        if not elts or not all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts
        ):
            return None
        return [e.value for e in elts]

    @classmethod
    def decorator_scopes(cls) -> list[tuple[str, int, list[str] | None]]:
        """``(module, lineno, scopes)`` for every ``has_permission(...)`` call."""
        calls = []
        for path in _source_modules():
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError:  # pragma: no cover -- defensive
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "has_permission"
                ):
                    calls.append(
                        (
                            str(path.relative_to(BACKEND_ROOT)),
                            node.lineno,
                            cls._literal_scopes(node),
                        )
                    )
        return calls

    def test_decorated_routes_were_found(self):
        """Guard the guard: a renamed decorator must not silently empty the sweep."""
        self.assertGreater(len(self.decorator_scopes()), 50)

    def test_every_decorator_scope_is_registered(self):
        offenders = [
            f"{module}:{lineno} {sorted(set(scopes) - set(PINNED_SCOPES))}"
            for module, lineno, scopes in self.decorator_scopes()
            if scopes and set(scopes) - set(PINNED_SCOPES)
        ]
        self.assertEqual(offenders, [], "@has_permission names unregistered scope(s)")

    def test_every_decorator_argument_is_a_literal_list(self):
        """Indirection would put the scopes out of reach of the check above."""
        offenders = [
            f"{module}:{lineno}"
            for module, lineno, scopes in self.decorator_scopes()
            if scopes is None
        ]
        self.assertEqual(
            offenders, [], "@has_permission argument is not a literal list of scopes"
        )


class DuplicatedScopeListsTestCase(SimpleTestCase):
    """Two more copies of the registry live outside ``scopes.py``.

    Both drifted once already: each was written when the registry had 16 entries
    and neither learned about ``org:integrations``. It cost nothing only because
    that scope gates no route yet. Pinned against the literal so the next append
    cannot repeat it.
    """

    def test_oauth_valid_scopes_is_the_registry(self):
        """Spelled out at its call site rather than derived on purpose: what an
        OAuth client may request is an authorization decision, so a new scope
        should have to be added there by hand -- and this is what asks."""
        self.assertEqual(VALID_SCOPES, list(PINNED_SCOPES))

    def test_oauth_default_scopes_are_registered(self):
        """The read-mostly set a client gets when it asks for nothing. A subset
        by design, so only membership is pinned."""
        self.assertEqual(sorted(set(DEFAULT_SCOPES) - set(PINNED_SCOPES)), [])

    def test_bootstrap_dev_grants_the_whole_registry(self):
        """The dev token AGENTS.md documents as having "all scopes"."""
        self.assertEqual(ALL_SCOPES, list(PINNED_SCOPES))
