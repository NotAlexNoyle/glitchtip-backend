"""
Partition-pruning guard for the integration test run.

Test-only: nothing outside ``glitchtip.test_runner.IntegrationTestRunner``
imports this module, so it never loads in production.

Every statement the suite runs against a partitioned table is EXPLAINed before
it runs, and the plan is checked for partitions the planner could not rule
out. A statement that opens *every* hash bucket under a time partition was not
narrowed by organization (cross-org); one that opens every time partition was
not narrowed by time (cross-time). When a plan fails, the statement is run once
more under EXPLAIN ANALYZE, in a savepoint that is rolled back, to tell a real
scan apart from one pruned at run time (a join or parameter the planner could
not see through) -- the second is reported as advisory, since it still plans
and locks every partition but executes only the ones that match. At 10,000 organizations and months of
retention either one turns a single lookup into thousands of relation locks,
and on a public endpoint that is an outage, not a slow query.

The rule is "opened all of them", not "opened more than one", so a batch that
spans a few organizations or a few days passes. That only works when the test
database has more buckets and more days than any one test touches, which the
integration runner arranges (16 buckets, two weeks of past partitions).

Findings are reported against the code that owns the query: the innermost
repository frame outside shared plumbing (raw SQL helpers, pagination,
middleware), with its callers. Queries issued by test code itself
(assertions, fixtures) are ignored. Approved exceptions live in ``partition_guard_allowlist.py``.
"""

import asyncio
import contextvars
import json
import os
import re
import sys
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from asgiref.sync import SyncToAsync
from django.db.backends.utils import CursorWrapper
from django_async_backend.db.backends.utils import AsyncCursorWrapper

from .partition_guard_allowlist import ALLOWLIST

REPO_ROOT = Path(__file__).resolve().parents[2]
_THIS_FILE = str(Path(__file__).resolve())
_EXPLAINABLE = re.compile(
    r"^\s*\(?\s*(SELECT|WITH|UPDATE|DELETE|INSERT|MERGE)\b", re.IGNORECASE
)
_SAVEPOINT = "partition_guard"

CROSS_ORG = "cross_org"
CROSS_TIME = "cross_time"


@dataclass
class Finding:
    kind: str
    table: str
    detail: str
    runtime_pruned: bool
    site: str
    chain: list[str]
    test: str
    sql: str


class _Node:
    __slots__ = ("children", "is_default", "name", "parent", "strategy")

    def __init__(self, name):
        self.name = name
        self.parent = None
        self.strategy = None  # partition strategy of THIS node's children
        self.is_default = False
        self.children = []


_TREE_SQL = """
SELECT c.relname, p.relname, pt.partstrat,
       pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'
FROM pg_class c
LEFT JOIN pg_inherits i ON i.inhrelid = c.oid
LEFT JOIN pg_class p ON p.oid = i.inhparent
LEFT JOIN pg_partitioned_table pt ON pt.partrelid = c.oid
WHERE c.relkind IN ('p', 'r') AND (c.relispartition OR c.relkind = 'p')
"""


class _PartitionTree:
    def __init__(self, rows):
        self.nodes: dict[str, _Node] = {}
        for name, parent, strategy, is_default in rows:
            node = self.nodes.setdefault(name, _Node(name))
            node.strategy = strategy
            node.is_default = bool(is_default)
            if parent:
                parent_node = self.nodes.setdefault(parent, _Node(parent))
                node.parent = parent_node
                parent_node.children.append(node)
        self.roots = {n.name for n in self.nodes.values() if n.parent is None}
        # Longest first so "logs_logevent_20260101" is matched to its own root
        # before any shorter root that happens to prefix it.
        self._root_pattern = re.compile(
            "|".join(re.escape(r) for r in sorted(self.roots, key=len, reverse=True))
        )

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
            if not node.children:
                continue
            real = [c for c in node.children if not c.is_default]
            if len(real) < 2:
                continue
            hit = [c for c in real if c.name in touched]
            if len(hit) < len(real):
                continue
            kind = {"h": CROSS_ORG, "r": CROSS_TIME}.get(node.strategy)
            if kind is None:
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


async def _afetch(cursor, fetch):
    if fetch == "one":
        return await cursor.fetchone()
    if fetch == "all":
        return await cursor.fetchall()
    return None


def _relation_names(plan, executed: bool = False) -> set[str]:
    """Relation names a plan scans. With ``executed``, only those an
    EXPLAIN ANALYZE plan actually ran (``Actual Loops`` above zero)."""
    names = set()
    stack = [plan]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "Relation Name" in item and (
                not executed or item.get("Actual Loops", 0) > 0
            ):
                names.add(item["Relation Name"])
            for value in item.values():
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return names


# --- call-site attribution ---------------------------------------------------

# The task that awaited the sync_to_async call running on this thread. The
# ORM's async methods hop to a worker thread, whose own stack starts at the
# executor, so without this the caller of ``afirst()`` would be lost.
_awaiting_task: contextvars.ContextVar[asyncio.Task | None] = contextvars.ContextVar(
    "partition_guard_awaiting_task", default=None
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
        or path.name == "test_runner.py"
    )


def _describe(filename: str, name: str, lineno: int) -> str:
    rel = os.path.relpath(filename, REPO_ROOT)
    return f"{rel}::{name}:{lineno}"


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
        frames.append((frame.f_code.co_filename, frame.f_code.co_name, frame.f_lineno))
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
        frames = [
            (f.f_code.co_filename, f.f_code.co_name, f.f_lineno)
            for f in _task_frames(task)
        ] + frames[hop + 1 :]
    chain = []
    for filename, name, lineno in reversed(frames):
        if not _is_repo_code(filename):
            continue
        if _is_test_code(filename):
            break
        chain.append(_describe(filename, name, lineno))
    if not chain:
        return None if any(_is_repo_code(f[0]) for f in frames) else ["<unknown>"]
    return chain


def _site_key(site: str) -> str:
    """Allowlist key: the site without its line number, so it survives edits."""
    return site.rsplit(":", 1)[0]


# --- the guard ---------------------------------------------------------------


class PartitionGuard:
    def __init__(self, report_path: Path):
        self.report_path = report_path
        self.trees: dict[str, _PartitionTree] = {}
        self.current_test = "<setup>"
        self._local = threading.local()
        self._originals = {}

    # Installation. Patching the two cursor classes, rather than registering an
    # execute_wrapper per connection, covers every connection either stack
    # opens -- ORM, raw_sql helpers, and async-backend cursors alike.
    def install(self):
        guard = self
        sync_orig = CursorWrapper._execute_with_wrappers
        async_orig = AsyncCursorWrapper._execute_with_wrappers
        s2a_orig = SyncToAsync.__call__

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

        self._originals = {
            (CursorWrapper, "_execute_with_wrappers"): sync_orig,
            (AsyncCursorWrapper, "_execute_with_wrappers"): async_orig,
            (SyncToAsync, "__call__"): s2a_orig,
        }
        CursorWrapper._execute_with_wrappers = sync_execute
        AsyncCursorWrapper._execute_with_wrappers = async_execute
        SyncToAsync.__call__ = s2a_call
        self.report_path.unlink(missing_ok=True)

    def uninstall(self):
        for (cls, attr), orig in self._originals.items():
            setattr(cls, attr, orig)
        self._originals = {}

    # Checking
    def _candidate(self, db, sql) -> bool:
        if getattr(self._local, "busy", False):
            return False
        if not isinstance(sql, str) or not _EXPLAINABLE.match(sql):
            return False
        tree = self.trees.get(db.settings_dict["NAME"])
        # No tree yet means the catalog has not been read for this database;
        # let the check build it.
        return tree is None or tree.mentions_partitioned(sql)

    def _steps(self, db, sql, params):
        """The check as a sequence of statements, shared by the sync and async
        paths. Yields ``(sql, params, fetch)`` and receives each result; the
        driver throws any database error back in.

        Returns ``(planned, executed)``: the unpruned dimensions of the plan,
        and of the partitions that actually ran. The second pass only happens
        when the first finds something, because it executes the statement.
        """
        name = db.settings_dict["NAME"]
        if name not in self.trees:
            self.trees[name] = _PartitionTree((yield _TREE_SQL, None, "all"))
        tree = self.trees[name]
        if not tree.mentions_partitioned(sql):
            return None
        # EXPLAIN ANALYZE runs the statement, so everything happens inside a
        # savepoint that is always rolled back. Ask the server rather than
        # trusting in_atomic_block: SAVEPOINT fails only outside a transaction
        # (autocommit), and only then is it safe to open one of our own -- a
        # BEGIN inside a transaction is merely a warning, and the ROLLBACK
        # would then discard the caller's work.
        try:
            yield f"SAVEPOINT {_SAVEPOINT}", None, None
            end = [
                f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}",
                f"RELEASE SAVEPOINT {_SAVEPOINT}",
            ]
        except Exception as e:
            if getattr(e, "sqlstate", None) != "25P01":  # no_active_sql_transaction
                # The transaction was already aborted before we got here; the
                # real statement will raise the same error on its own.
                return None
            try:
                yield "BEGIN", None, None
            except Exception:
                return None
            end = ["ROLLBACK"]
        planned = executed = None
        try:
            plan = (yield "EXPLAIN (FORMAT JSON) " + sql, params, "one")[0]
            relations = _relation_names(_loads(plan))
            if any(
                tree.mentions_partitioned(r) and r not in tree.nodes for r in relations
            ):
                # A test created partitions since the catalog was read.
                self.trees.pop(name, None)
                relations = set()
            planned = tree.analyze(relations)
            if planned:
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
            pass
        try:
            for stmt in end:
                yield stmt, None, None
        except Exception:
            pass
        return planned, executed

    def check_sync(self, wrapper, sql, params):
        if not self._candidate(wrapper.db, sql):
            return
        chain = _call_chain()
        if chain is None:
            return
        raw = wrapper.cursor
        steps = self._steps(wrapper.db, sql, params)
        self._local.busy = True
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
            return
        finally:
            self._local.busy = False

    async def check_async(self, wrapper, sql, params):
        if not self._candidate(wrapper.db, sql):
            return
        chain = _call_chain()
        if chain is None:
            return
        raw = wrapper.cursor
        steps = self._steps(wrapper.db, sql, params)
        self._local.busy = True
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
                    result = await _afetch(raw, fetch)
                except Exception as e:
                    error = e
        except Exception:
            # The guard must never break the statement it is inspecting.
            return
        finally:
            self._local.busy = False

    def _record(self, outcome, sql, chain):
        if not outcome or not outcome[0]:
            return
        planned, executed = outcome
        # A dimension the executed partitions still fail to narrow is a real
        # scan. One only the plan fails is pruned at run time (a join or a
        # parameter the planner could not see through); cheaper, but the
        # planner still locks every partition it kept.
        still = None if executed is None else {(k, t) for k, t, _ in executed}
        with self.report_path.open("a") as f:
            for kind, table, detail in planned:
                finding = Finding(
                    kind=kind,
                    table=table,
                    detail=detail,
                    runtime_pruned=still is not None and (kind, table) not in still,
                    site=chain[0],
                    chain=chain,
                    test=self.current_test,
                    sql=" ".join(sql.split())[:600],
                )
                f.write(json.dumps(asdict(finding)) + "\n")


# --- reporting ---------------------------------------------------------------


def load_findings(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    with report_path.open() as f:
        return [Finding(**json.loads(line)) for line in f if line.strip()]


def is_allowed(finding: Finding) -> bool:
    """An entry may name any frame in the chain: the helper that builds the
    query (approves every caller) or one endpoint that uses it (approves just
    that one)."""
    return any(
        ALLOWLIST.get(_site_key(frame), {}).get(finding.kind) for frame in finding.chain
    )


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


def _owner(chain: list[str]) -> str:
    return next((f for f in chain if not _is_plumbing(f)), chain[0])


def summarize(findings: list[Finding], stream=sys.stderr) -> int:
    """Print findings grouped by the code that owns the query; return how many
    of those sites scan every partition without an allowlist entry."""
    # (site, kind) -> hits
    by_kind: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        by_kind[(_site_key(_owner(finding.chain)), finding.kind)].append(finding)

    def verdict(items: list[Finding]) -> str:
        if all(is_allowed(i) for i in items):
            return "allowed"
        # Pruned at run time only if every hit was; one real scan anywhere
        # makes the site blocking.
        return "advisory" if all(i.runtime_pruned for i in items) else "blocking"

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
                    _site_key(f)
                    for i in items
                    for f in i.chain[i.chain.index(_owner(i.chain)) + 1 :][-1:]
                    if not _is_plumbing(f)
                }
            )
            write(f"\n  [{', '.join(sorted(kinds))}] {site}\n")
            if callers:
                write(f"    via: {', '.join(callers)}\n")
            details = sorted({i.detail for i in items})
            write(f"    tables: {', '.join(tables)} ({'; '.join(details)})\n")
            write(f"    hits: {len(items)} in {len(tests)} test(s), e.g. {tests[0]}\n")
            if show_sql:
                write(f"    sql: {first.sql}\n")
    write(
        "\nFix the query to filter on organization_id and a time bound on the"
        "\npartition key, or add an approved entry to"
        "\nglitchtip/test_utils/partition_guard_allowlist.py.\n"
    )
    return len(sections.get("blocking", {}))
