"""
Partition-pruning guard for the integration test run.

Test-only: ``glitchtip.test_runner`` imports this module, but only
``IntegrationTestRunner`` installs it, and the test runner never loads in
production.

Every statement the suite runs against a partitioned table is EXPLAINed before
it runs, and the plan is checked for partitions the planner could not rule
out. A statement that opens *every* organization hash bucket under a time
partition was not narrowed by organization (cross-org); one that opens every
time partition was not narrowed by time (cross-time).

When a plan fails and the connection is inside a transaction, the statement is
run once more under EXPLAIN ANALYZE in a savepoint that is always rolled back,
to tell a real scan from one pruned at run time (a join or parameter the
planner could not see through). The second is reported as advisory: it still
plans and locks every partition but executes only the ones that match. Outside
a transaction there is no savepoint to roll back to -- an async autocommit
connection does not even keep one session between statements -- so the
statement is never re-run there and the finding stays unverified, which counts
as blocking.

The rule is "opened all of them", not "opened more than one", so a batch that
spans a few organizations or a few days passes. That only works when the test
database has more buckets and more history than any query's window, which the
integration runner arranges (16 buckets; two weeks of daily and three of
weekly past partitions). A query whose window is wider than that history --
"the last 90 days" -- opens every partition here and must be allowlisted.

Findings are reported against the code that owns the query: the innermost
repository frame outside shared plumbing (raw SQL helpers, pagination,
middleware), or the request's URL route when every frame is plumbing, as when
pagination evaluates a view's lazy queryset. Queries issued by test code
itself (assertions, fixtures) are ignored. Approved exceptions live in
``partition_guard_allowlist.py``.

Not covered: ``executemany``, ``cursor.copy()``, SQL that starts with a
comment, and anything that does not go through a Django cursor wrapper, such
as the Rust envelope-ingest path.
"""

import asyncio
import contextvars
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from asgiref.sync import SyncToAsync
from django.core.handlers.base import BaseHandler
from django.db.backends.utils import CursorWrapper
from django_async_backend.db.backends.utils import AsyncCursorWrapper

from .partition_guard_allowlist import ALLOWLIST

REPO_ROOT = Path(__file__).resolve().parents[2]
_THIS_FILE = str(Path(__file__).resolve())
_EXPLAINABLE = re.compile(
    r"^\s*\(?\s*(SELECT|WITH|UPDATE|DELETE|INSERT|MERGE)\b", re.IGNORECASE
)
# Re-running an INSERT under ANALYZE advances sequences even when rolled back.
_INSERTS = re.compile(r"\bINSERT\b", re.IGNORECASE)
_SAVEPOINT = "partition_guard"
_NO_TRANSACTION = "25P01"  # no_active_sql_transaction

CROSS_ORG = "cross_org"
CROSS_TIME = "cross_time"


@dataclass
class Finding:
    kind: str
    table: str
    detail: str
    # True: pruned at run time. False: a real scan. None: not re-run to find
    # out (autocommit, or an INSERT).
    runtime_pruned: bool | None
    site: str
    chain: list[str]
    test: str
    sql: str
    route: str | None = None


class _Node:
    __slots__ = ("children", "is_default", "key", "name", "parent", "strategy")

    def __init__(self, name):
        self.name = name
        self.parent = None
        self.strategy = None  # partition strategy of THIS node's children
        self.key = ""  # partition key of THIS node's children
        self.is_default = False
        self.children = []


_TREE_SQL = """
SELECT c.relname, p.relname, pt.partstrat,
       pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT',
       CASE WHEN pt.partrelid IS NOT NULL THEN pg_get_partkeydef(c.oid) END
FROM pg_class c
LEFT JOIN pg_inherits i ON i.inhrelid = c.oid
LEFT JOIN pg_class p ON p.oid = i.inhparent
LEFT JOIN pg_partitioned_table pt ON pt.partrelid = c.oid
WHERE c.relkind IN ('p', 'r') AND (c.relispartition OR c.relkind = 'p')
"""


class _PartitionTree:
    def __init__(self, rows):
        self.nodes: dict[str, _Node] = {}
        for name, parent, strategy, is_default, key in rows:
            node = self.nodes.setdefault(name, _Node(name))
            node.strategy = strategy
            node.key = key or ""
            node.is_default = bool(is_default)
            if parent:
                parent_node = self.nodes.setdefault(parent, _Node(parent))
                node.parent = parent_node
                parent_node.children.append(node)
        self.roots = {n.name for n in self.nodes.values() if n.parent is None}
        self._root_pattern = re.compile("|".join(re.escape(r) for r in self.roots))

    def mentions_partitioned(self, sql: str) -> bool:
        return bool(self.roots) and self._root_pattern.search(sql) is not None

    def root_of(self, node: _Node) -> _Node:
        while node.parent is not None:
            node = node.parent
        return node

    def analyze(self, relations: set[str]) -> list[tuple[str, str, str]]:
        """Return (kind, table, detail) for each dimension the plan failed to
        prune. ``relations`` are the relation names a plan scans."""
        touched: set[str] = set()
        for rel in relations:
            node = self.nodes.get(rel)
            if node is None or node.parent is None or node.is_default:
                continue
            # Everything under a DEFAULT partition is test scaffolding; judge
            # the plan by the real partitions only.
            while node is not None:
                if node.is_default:
                    break
                touched.add(node.name)
                node = node.parent
        results = []
        seen = set()
        for name in touched:
            node = self.nodes[name]
            real = [c for c in node.children if not c.is_default]
            if len(real) < 2 or any(c.name not in touched for c in real):
                continue
            if node.strategy == "r":
                kind = CROSS_TIME
            elif node.strategy == "h" and "organization_id" in node.key:
                kind = CROSS_ORG
            else:
                continue
            table = self.root_of(node).name
            if (kind, table) in seen:
                continue
            seen.add((kind, table))
            unit = "hash buckets" if kind == CROSS_ORG else "time partitions"
            where = "" if node.name == table else f" of {node.name}"
            results.append((kind, table, f"all {len(real)} {unit}{where}"))
        return results


def _loads(plan):
    return json.loads(plan) if isinstance(plan, (str, bytes)) else plan


def _fetch(cursor, fetch):
    if fetch == "one":
        return cursor.fetchone()
    if fetch == "all":
        return cursor.fetchall()
    return None


async def _fetch_async(cursor, fetch):
    if fetch == "one":
        return await cursor.fetchone()
    if fetch == "all":
        return await cursor.fetchall()
    return None


def _relation_names(plan, executed: bool = False) -> set[str]:
    """Relation names a plan scans.

    With ``executed``, only those an EXPLAIN ANALYZE plan actually ran. A scan
    counts as skipped only when its Append ran and it did not; if the Append
    itself never ran (an empty outer side, say), nothing was learned about its
    children and they count as scanned.
    """
    names = set()
    stack = [(plan, True)]
    while stack:
        item, append_ran = stack.pop()
        if isinstance(item, list):
            stack.extend((i, append_ran) for i in item)
            continue
        if not isinstance(item, dict):
            continue
        loops = item.get("Actual Loops") or 0
        if "Relation Name" in item and (not executed or loops > 0 or not append_ran):
            names.add(item["Relation Name"])
        if item.get("Node Type") in ("Append", "Merge Append"):
            append_ran = loops > 0
        for value in item.values():
            if isinstance(value, (dict, list)):
                stack.append((value, append_ran))
    return names


# --- call-site attribution ---------------------------------------------------

# The task that awaited the sync_to_async call running on this thread. The
# ORM's async methods hop to a worker thread, whose own stack starts at the
# executor, so without this the caller of ``afirst()`` would be lost.
_awaiting_task: contextvars.ContextVar[asyncio.Task | None] = contextvars.ContextVar(
    "partition_guard_awaiting_task", default=None
)
# The URL route of the request being handled, for queries whose every frame is
# plumbing -- a lazy queryset evaluated by pagination after the view returned.
_route: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "partition_guard_route", default=None
)


def _task_frames(task: asyncio.Task):
    """Frames of a suspended task, outermost first, following the await chain."""
    frames = []
    coro = task.get_coro()
    while coro is not None:
        frame = getattr(coro, "cr_frame", None) or getattr(coro, "gi_frame", None)
        if frame is not None:
            frames.append(frame)
        coro = getattr(coro, "cr_await", None) or getattr(coro, "gi_yieldfrom", None)
    return frames


def _in_event_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def _is_repo_code(filename: str) -> bool:
    return (
        filename.startswith(str(REPO_ROOT))
        and "/.venv/" not in filename
        and "site-packages" not in filename
        and filename != _THIS_FILE
        and filename != str(REPO_ROOT / "manage.py")
    )


def _is_test_code(filename: str) -> bool:
    path = Path(filename)
    return (
        "tests" in path.parts
        # The seed-data API only exists when ENABLE_TEST_API is set.
        or "test_api" in path.parts
        or path.name.startswith("test")
        or "test_utils" in path.parts
    )


def _frame_tuple(frame):
    return frame.f_code.co_filename, frame.f_code.co_qualname, frame.f_lineno


def _call_chain() -> list[str] | None:
    """Repository frames that led to the query, innermost first, stopping at
    the first test frame.

    Returns None when the innermost repository frame is test code, meaning the
    query is the test's own business (an assertion or a fixture) rather than
    the code under test.
    """
    frames = []
    frame = sys._getframe(1)
    while frame is not None:
        frames.append(_frame_tuple(frame))
        frame = frame.f_back
    frames.reverse()
    task = _awaiting_task.get()
    if task is not None and not _in_event_loop():
        # We are the sync half of a sync_to_async hop. This thread's stack
        # above the hop belongs to whoever runs the event loop (often the test
        # runner, on the main thread), not to the caller; splice the awaiting
        # task's coroutine chain in its place.
        hop = max(
            (i for i, f in enumerate(frames) if f[0].endswith("asgiref/sync.py")),
            default=-1,
        )
        frames = [_frame_tuple(f) for f in _task_frames(task)] + frames[hop + 1 :]
    chain = []
    for filename, name, lineno in reversed(frames):
        if not _is_repo_code(filename):
            continue
        if _is_test_code(filename):
            break
        rel = os.path.relpath(filename, REPO_ROOT)
        chain.append(f"{rel}::{name}:{lineno}")
    if not chain:
        return None if any(_is_repo_code(f[0]) for f in frames) else ["<unknown>"]
    return chain


def _site_key(site: str) -> str:
    """Allowlist key: the site without its line number, so it survives edits."""
    return site if site.startswith("route:") else site.rsplit(":", 1)[0]


# Shared plumbing that runs other code's queries. A finding is reported against
# the first frame outside these, so the report names the code that chose the
# query rather than the helper that sent it.
_PLUMBING = (
    "apps/shared/raw_sql.py",
    "glitchtip/api/pagination.py",
    "glitchtip/api/permissions.py",
    "glitchtip/async_db.py",
    "glitchtip/compression.py",
)


def _is_plumbing(frame: str) -> bool:
    return frame.startswith(_PLUMBING)


def _owner(chain: list[str], route: str | None) -> str:
    owner = next((f for f in chain if not _is_plumbing(f)), None)
    if owner is None:
        return f"route:{route}" if route else chain[0]
    return owner


# --- the guard ---------------------------------------------------------------


class _Pending:
    """Statements that must run if the check is interrupted mid-way."""

    __slots__ = ("statements",)

    def __init__(self):
        self.statements: list[str] = []


class PartitionGuard:
    def __init__(self, report_path: Path):
        self.report_path = report_path
        self.trees: dict[str, _PartitionTree] = {}
        self.current_test = "<setup>"
        self.errors = 0
        self._originals = {}
        # Tests of the guard itself swap this to have their own queries
        # treated as app code, without touching the installed guard.
        self.call_chain = _call_chain

    def start_test(self, test_id: str):
        self.current_test = test_id
        # Tests create and drop partitions (and roll them back); read the
        # catalog afresh rather than judge a plan against a stale layout.
        self.trees.clear()

    # Installation. Patching the two cursor classes, rather than registering an
    # execute_wrapper per connection, covers every connection either stack
    # opens -- ORM, raw_sql helpers, and async-backend cursors alike.
    def install(self):
        guard = self
        sync_orig = CursorWrapper._execute_with_wrappers
        async_orig = AsyncCursorWrapper._execute_with_wrappers
        s2a_orig = SyncToAsync.__call__
        resolve_orig = BaseHandler.resolve_request

        def sync_execute(self, sql, params, many, executor):
            if not many:
                guard.check_sync(self, sql, params)
            return sync_orig(self, sql, params, many, executor)

        async def async_execute(self, sql, params, many, executor):
            if not many:
                await guard.check_async(self, sql, params)
            return await async_orig(self, sql, params, many, executor)

        async def s2a_call(self, *args, **kwargs):
            try:
                task = asyncio.current_task()
            except RuntimeError:
                task = None
            token = _awaiting_task.set(task)
            try:
                return await s2a_orig(self, *args, **kwargs)
            finally:
                _awaiting_task.reset(token)

        def resolve_request(self, request):
            match = resolve_orig(self, request)
            _route.set(match.route)
            return match

        self._originals = {
            (CursorWrapper, "_execute_with_wrappers"): sync_orig,
            (AsyncCursorWrapper, "_execute_with_wrappers"): async_orig,
            (SyncToAsync, "__call__"): s2a_orig,
            (BaseHandler, "resolve_request"): resolve_orig,
        }
        CursorWrapper._execute_with_wrappers = sync_execute
        AsyncCursorWrapper._execute_with_wrappers = async_execute
        SyncToAsync.__call__ = s2a_call
        BaseHandler.resolve_request = resolve_request
        self.report_path.unlink(missing_ok=True)

    def uninstall(self):
        for (cls, attr), orig in self._originals.items():
            setattr(cls, attr, orig)
        self._originals = {}

    # Checking
    def _candidate(self, db, sql) -> bool:
        if not isinstance(sql, str) or not _EXPLAINABLE.match(sql):
            return False
        if getattr(db, "needs_rollback", False):
            return False  # Django will refuse to run the statement anyway
        tree = self.trees.get(db.settings_dict["NAME"])
        # No tree yet means the catalog has not been read for this database;
        # let the check build it.
        return tree is None or tree.mentions_partitioned(sql)

    def _steps(self, db, sql, params, pending: _Pending):
        """The check as a sequence of statements, shared by the sync and async
        paths. Yields ``(sql, params, fetch)`` and receives each result; the
        driver throws any database error back in, and runs
        ``pending.statements`` if it is interrupted.

        Returns ``(planned, executed)``: the unpruned dimensions of the plan,
        and of the partitions that actually ran -- None when the statement was
        not re-run.
        """
        name = db.settings_dict["NAME"]
        if name not in self.trees:
            self.trees[name] = _PartitionTree((yield _TREE_SQL, None, "all"))
        if not self.trees[name].mentions_partitioned(sql):
            return None
        # A savepoint both protects the caller's transaction and proves there
        # is one: it fails only outside a transaction (autocommit), and there
        # the statement must not be re-run, since nothing would roll it back.
        try:
            yield f"SAVEPOINT {_SAVEPOINT}", None, None
            in_transaction = True
            pending.statements = [
                f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}",
                f"RELEASE SAVEPOINT {_SAVEPOINT}",
            ]
        except Exception as e:
            if getattr(e, "sqlstate", None) != _NO_TRANSACTION:
                # The transaction was already aborted before we got here; the
                # real statement will raise the same error on its own.
                return None
            in_transaction = False
        planned = executed = None
        try:
            plan = (yield "EXPLAIN (FORMAT JSON) " + sql, params, "one")[0]
            relations = _relation_names(_loads(plan))
            tree = self.trees[name]
            if any(
                tree.mentions_partitioned(r) and r not in tree.nodes for r in relations
            ):
                # The test created partitions since the catalog was read.
                tree = _PartitionTree((yield _TREE_SQL, None, "all"))
                self.trees[name] = tree
            planned = tree.analyze(relations)
            if planned and in_transaction and not _INSERTS.search(sql):
                analyzed = (
                    yield (
                        "EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF, FORMAT JSON) "
                        + sql,
                        params,
                        "one",
                    )
                )[0]
                executed = tree.analyze(
                    _relation_names(_loads(analyzed), executed=True)
                )
        except Exception:
            self.errors += 1
        statements, pending.statements = pending.statements, []
        for stmt in statements:
            try:
                yield stmt, None, None
            except Exception:
                self.errors += 1
        return planned, executed

    def _begin(self, wrapper, sql, params):
        if not self._candidate(wrapper.db, sql):
            return None
        chain = self.call_chain()
        if chain is None:
            return None
        pending = _Pending()
        return self._steps(wrapper.db, sql, params, pending), pending, chain

    def check_sync(self, wrapper, sql, params):
        started = self._begin(wrapper, sql, params)
        if started is None:
            return
        steps, pending, chain = started
        raw = wrapper.cursor
        result = error = None
        try:
            while True:
                try:
                    step = steps.throw(error) if error else steps.send(result)
                except StopIteration as stop:
                    self._record(stop.value, sql, chain)
                    return
                stmt, stmt_params, fetch = step
                result = error = None
                try:
                    raw.execute(stmt, stmt_params)
                    result = _fetch(raw, fetch)
                except Exception as e:
                    error = e
        except Exception:
            # The guard must never break the statement it is inspecting.
            self.errors += 1
        except BaseException:
            for stmt in pending.statements:
                try:
                    raw.execute(stmt)
                except Exception:
                    pass
            raise

    async def check_async(self, wrapper, sql, params):
        started = self._begin(wrapper, sql, params)
        if started is None:
            return
        steps, pending, chain = started
        raw = wrapper.cursor
        result = error = None
        try:
            while True:
                try:
                    step = steps.throw(error) if error else steps.send(result)
                except StopIteration as stop:
                    self._record(stop.value, sql, chain)
                    return
                stmt, stmt_params, fetch = step
                result = error = None
                try:
                    await raw.execute(stmt, stmt_params)
                    result = await _fetch_async(raw, fetch)
                except Exception as e:
                    error = e
        except Exception:
            self.errors += 1
        except BaseException:
            # Cancelled mid-check: undo the savepoint before the caller's
            # transaction can commit what EXPLAIN ANALYZE did.
            for stmt in pending.statements:
                try:
                    await asyncio.shield(raw.execute(stmt))
                except Exception:
                    pass
            raise

    def _record(self, outcome, sql, chain):
        if not outcome or not outcome[0]:
            return
        planned, executed = outcome
        # A dimension the executed partitions still fail to narrow is a real
        # scan. One only the plan fails is pruned at run time; cheaper, but the
        # planner still locks every partition it kept.
        still = None if executed is None else {(k, t) for k, t, _ in executed}
        route = _route.get()
        with self.report_path.open("a") as f:
            for kind, table, detail in planned:
                finding = Finding(
                    kind=kind,
                    table=table,
                    detail=detail,
                    runtime_pruned=None
                    if still is None
                    else (kind, table) not in still,
                    site=_owner(chain, route),
                    chain=chain,
                    test=self.current_test,
                    sql=" ".join(sql.split())[:600],
                    route=route,
                )
                f.write(json.dumps(asdict(finding)) + "\n")


# --- reporting ---------------------------------------------------------------


def load_findings(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    with report_path.open() as f:
        return [Finding(**json.loads(line)) for line in f if line.strip()]


def is_allowed(finding: Finding) -> bool:
    """An entry may name any frame in the chain -- the helper that builds the
    query (approves every caller) or one endpoint that uses it (approves just
    that one) -- or the request's route."""
    keys = [_site_key(frame) for frame in finding.chain]
    if finding.route:
        keys.append(f"route:{finding.route}")
    return any(ALLOWLIST.get(key, {}).get(finding.kind) for key in keys)


def summarize(findings: list[Finding], errors: int = 0, stream=sys.stderr) -> int:
    """Print findings grouped by the code that owns the query; return how many
    of those sites scan every partition without an allowlist entry."""
    by_kind: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        by_kind[(_site_key(finding.site), finding.kind)].append(finding)

    def verdict(items: list[Finding]) -> str:
        open_items = [i for i in items if not is_allowed(i)]
        if not open_items:
            return "allowed"
        # Pruned at run time only if every unapproved hit was shown to be;
        # one real or unverified scan makes the site blocking.
        if all(i.runtime_pruned for i in open_items):
            return "advisory"
        return "blocking"

    # verdict -> site -> kind -> hits
    sections: dict[str, dict[str, dict[str, list[Finding]]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    for (site, kind), items in by_kind.items():
        sections[verdict(items)][site][kind] = items

    write = stream.write
    write("\n" + "=" * 70 + "\n")
    write("Partition pruning guard\n")
    write("=" * 70 + "\n")
    if errors:
        write(f"{errors} statement(s) could not be checked (guard errors).\n")
    if not by_kind:
        write("No unpruned partition scans.\n")
        return 0
    titles = (
        ("blocking", "UNPRUNED -- scans every partition", True),
        (
            "advisory",
            "Pruned only at run time -- plans and locks every partition",
            True,
        ),
        ("allowed", "Allowlisted", False),
    )
    for verdict_name, title, show_sql in titles:
        group = sections.get(verdict_name)
        if not group:
            continue
        write(f"\n{title}: {len(group)} call site(s)\n")
        for site, kinds in sorted(group.items()):
            items = [i for hits in kinds.values() for i in hits]
            first = items[0]
            tables = sorted({i.table for i in items})
            tests = sorted({i.test for i in items})
            callers = sorted(
                {
                    _site_key(outer)
                    for i in items
                    if i.site in i.chain
                    for outer in i.chain[i.chain.index(i.site) + 1 :][-1:]
                    if not _is_plumbing(outer)
                }
            )
            unverified = sum(1 for i in items if i.runtime_pruned is None)
            write(f"\n  [{', '.join(sorted(kinds))}] {site}\n")
            if callers:
                write(f"    via: {', '.join(callers)}\n")
            details = sorted({i.detail for i in items})
            write(f"    tables: {', '.join(tables)} ({'; '.join(details)})\n")
            write(f"    hits: {len(items)} in {len(tests)} test(s), e.g. {tests[0]}\n")
            if unverified and verdict_name == "blocking":
                write(
                    f"    {unverified} hit(s) unverified: outside a transaction"
                    " or an INSERT, so not re-run to check run-time pruning\n"
                )
            if show_sql:
                write(f"    sql: {first.sql}\n")
    write(
        "\nFix the query to filter on organization_id and a time bound on the"
        "\npartition key, or add an approved entry to"
        "\nglitchtip/test_utils/partition_guard_allowlist.py.\n"
    )
    return len(sections.get("blocking", {}))
