import io
import tempfile
from pathlib import Path
from unittest import mock

from django.db import connection
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django_async_backend.db import async_connections
from model_bakery import baker

from apps.issue_events.models import IssueIndex

from . import generators  # noqa: F401  (registers baker gens)
from .partition_guard import (
    _NO_TRANSACTION,
    _SAVEPOINT,
    CROSS_ORG,
    CROSS_TIME,
    Finding,
    PartitionGuard,
    _call_chain,
    _PartitionTree,
    _Pending,
    _relation_names,
    is_allowed,
    summarize,
)

ROOT = "events"
DAYS = ["events_d1", "events_d2", "events_d3"]
BUCKETS = 4
ORG_KEY = "HASH (organization_id)"


def _tree():
    rows = [(ROOT, None, "r", False, "RANGE (id)")]
    rows.append(("events_default", ROOT, None, True, None))
    for day in DAYS:
        rows.append((day, ROOT, "h", False, ORG_KEY))
        for b in range(BUCKETS):
            rows.append((f"{day}_h{b}", day, None, False, None))
    rows.append(("index", None, "h", False, ORG_KEY))
    rows += [(f"index_h{b}", "index", None, False, None) for b in range(BUCKETS)]
    rows.append(("by_project", None, "h", False, "HASH (project_id)"))
    rows += [(f"by_project_h{b}", "by_project", None, False, None) for b in range(2)]
    return _PartitionTree(rows)


def _kinds(tree, relations):
    return {(kind, table) for kind, table, _ in tree.analyze(set(relations))}


ALL_EVENTS = [f"{day}_h{b}" for day in DAYS for b in range(BUCKETS)]


def _plan(relations, loops=None, append_loops=1):
    """A JSON plan with one Append over ``relations``. With ``loops``, an
    EXPLAIN ANALYZE plan: each relation's Actual Loops, zero if not given."""
    children = []
    for rel in relations:
        node = {"Node Type": "Seq Scan", "Relation Name": rel}
        if loops is not None:
            node["Actual Loops"] = loops.get(rel, 0)
        children.append(node)
    append = {"Node Type": "Append", "Plans": children}
    if loops is not None:
        append["Actual Loops"] = append_loops
    return [{"Plan": append}]


class PartitionTreeTests(SimpleTestCase):
    def test_fully_pruned(self):
        self.assertEqual(_kinds(_tree(), ["events_d2_h1"]), set())

    def test_some_buckets_some_days_is_fine(self):
        rels = ["events_d1_h0", "events_d1_h3", "events_d2_h0", "events_default"]
        self.assertEqual(_kinds(_tree(), rels), set())

    def test_every_bucket_is_cross_org(self):
        rels = [f"events_d2_h{b}" for b in range(BUCKETS)]
        self.assertEqual(_kinds(_tree(), rels), {(CROSS_ORG, ROOT)})

    def test_every_day_is_cross_time(self):
        rels = [f"{day}_h1" for day in DAYS]
        self.assertEqual(_kinds(_tree(), rels), {(CROSS_TIME, ROOT)})

    def test_unpruned_is_both(self):
        self.assertEqual(
            _kinds(_tree(), ALL_EVENTS), {(CROSS_ORG, ROOT), (CROSS_TIME, ROOT)}
        )

    def test_default_partition_is_ignored(self):
        rels = [f"{day}_h1" for day in DAYS[:2]] + ["events_default"]
        self.assertEqual(_kinds(_tree(), rels), set())

    def test_hash_only_table(self):
        tree = _tree()
        self.assertEqual(_kinds(tree, ["index_h2"]), set())
        rels = [f"index_h{b}" for b in range(BUCKETS)]
        self.assertEqual(_kinds(tree, rels), {(CROSS_ORG, "index")})

    def test_hash_on_another_column_is_not_cross_org(self):
        self.assertEqual(_kinds(_tree(), ["by_project_h0", "by_project_h1"]), set())

    def test_mentions_partitioned(self):
        tree = _tree()
        self.assertTrue(tree.mentions_partitioned('SELECT 1 FROM "events"'))
        self.assertFalse(tree.mentions_partitioned("SELECT 1 FROM projects"))


class RelationNamesTests(SimpleTestCase):
    def test_walks_nested_plans(self):
        plan = [
            {
                "Plan": {
                    "Node Type": "Append",
                    "Plans": [
                        {"Relation Name": "events_d1_h0"},
                        {"Plans": [{"Relation Name": "events_d2_h3"}]},
                    ],
                }
            }
        ]
        self.assertEqual(_relation_names(plan), {"events_d1_h0", "events_d2_h3"})

    def test_executed_only(self):
        plan = _plan(["events_d1_h0", "events_d1_h1"], loops={"events_d1_h0": 1})
        self.assertEqual(_relation_names(plan, executed=True), {"events_d1_h0"})

    def test_append_that_never_ran_counts_as_scanned(self):
        # An empty outer side leaves every child at zero loops; that says
        # nothing about pruning, so the children must not look skipped.
        plan = _plan(["events_d1_h0", "events_d1_h1"], loops={}, append_loops=0)
        self.assertEqual(
            _relation_names(plan, executed=True), {"events_d1_h0", "events_d1_h1"}
        )


class _DbError(Exception):
    def __init__(self, sqlstate):
        self.sqlstate = sqlstate


class _Db:
    settings_dict = {"NAME": "db"}


def _drive(guard, sql, results):
    """Run ``_steps`` against scripted results: ``results`` maps a statement
    prefix to what the database returns (or raises) for it. Returns the
    statements sent and the outcome."""
    steps = guard._steps(_Db(), sql, None, _Pending())
    sent = []
    value = error = None
    while True:
        try:
            stmt, _params, _fetch = steps.throw(error) if error else steps.send(value)
        except StopIteration as stop:
            return sent, stop.value
        sent.append(stmt)
        value = error = None
        for prefix, result in results.items():
            if stmt.startswith(prefix):
                if isinstance(result, Exception):
                    error = result
                else:
                    value = result
                break


class StepsTests(SimpleTestCase):
    def setUp(self):
        self.guard = PartitionGuard(Path("unused"))
        self.guard.trees["db"] = _tree()
        self.unpruned = (_plan(ALL_EVENTS),)

    def test_in_a_transaction_reruns_under_analyze_and_rolls_back(self):
        executed = _plan(ALL_EVENTS[:1], loops={ALL_EVENTS[0]: 1})
        sent, (planned, pruned) = _drive(
            self.guard,
            "SELECT * FROM events",
            {"EXPLAIN (FORMAT": self.unpruned, "EXPLAIN (ANALYZE": (executed,)},
        )
        self.assertEqual(sent[0], f"SAVEPOINT {_SAVEPOINT}")
        self.assertTrue(any(s.startswith("EXPLAIN (ANALYZE") for s in sent))
        self.assertEqual(
            sent[-2:],
            [f"ROLLBACK TO SAVEPOINT {_SAVEPOINT}", f"RELEASE SAVEPOINT {_SAVEPOINT}"],
        )
        self.assertEqual({k for k, _, _ in planned}, {CROSS_ORG, CROSS_TIME})
        self.assertEqual(pruned, [])

    def test_autocommit_never_reruns_the_statement(self):
        sent, (planned, executed) = _drive(
            self.guard,
            "UPDATE events SET n = n + 1",
            {
                "SAVEPOINT": _DbError(_NO_TRANSACTION),
                "EXPLAIN (FORMAT": self.unpruned,
            },
        )
        self.assertFalse(any("ANALYZE" in s or "BEGIN" in s for s in sent))
        self.assertTrue(planned)
        self.assertIsNone(executed)

    def test_an_insert_is_never_rerun(self):
        sent, (_planned, executed) = _drive(
            self.guard,
            "INSERT INTO t SELECT * FROM events",
            {"EXPLAIN (FORMAT": self.unpruned},
        )
        self.assertFalse(any(s.startswith("EXPLAIN (ANALYZE") for s in sent))
        self.assertIsNone(executed)
        self.assertEqual(sent[-1], f"RELEASE SAVEPOINT {_SAVEPOINT}")

    def test_aborted_transaction_is_left_alone(self):
        sent, outcome = _drive(
            self.guard, "SELECT * FROM events", {"SAVEPOINT": _DbError("25P02")}
        )
        self.assertEqual(sent, [f"SAVEPOINT {_SAVEPOINT}"])
        self.assertIsNone(outcome)

    def test_pruned_plan_is_not_rerun(self):
        sent, (planned, _executed) = _drive(
            self.guard,
            "SELECT * FROM events",
            {"EXPLAIN (FORMAT": (_plan(["events_d1_h0"]),)},
        )
        self.assertEqual(planned, [])
        self.assertFalse(any(s.startswith("EXPLAIN (ANALYZE") for s in sent))

    def test_unrelated_sql_is_skipped(self):
        sent, outcome = _drive(self.guard, "SELECT * FROM projects", {})
        self.assertEqual(sent, [])
        self.assertIsNone(outcome)


def _finding(kind, chain, runtime_pruned=False):
    return Finding(
        kind=kind,
        table=ROOT,
        detail="",
        runtime_pruned=runtime_pruned,
        site=chain[0],
        chain=chain,
        test="t",
        sql="",
    )


ALLOWLIST = "glitchtip.test_utils.partition_guard.ALLOWLIST"


class AllowlistTests(SimpleTestCase):
    chain = ["apps/a/helpers.py::paginate:10", "apps/a/api.py::list_things:40"]

    def test_any_frame_in_chain_matches(self):
        entries = {"apps/a/api.py::list_things": {CROSS_TIME: "LIMIT on id"}}
        with mock.patch.dict(ALLOWLIST, entries):
            self.assertTrue(is_allowed(_finding(CROSS_TIME, self.chain)))
            self.assertFalse(is_allowed(_finding(CROSS_ORG, self.chain)))

    def test_unlisted_site_is_not_allowed(self):
        entries = {"apps/b/api.py::other": {CROSS_TIME: "reason"}}
        with mock.patch.dict(ALLOWLIST, entries):
            self.assertFalse(is_allowed(_finding(CROSS_TIME, self.chain)))

    def test_route_matches(self):
        finding = _finding(CROSS_ORG, ["glitchtip/api/pagination.py::get:1"])
        finding.route = "api/0/things/"
        with mock.patch.dict(ALLOWLIST, {"route:api/0/things/": {CROSS_ORG: "r"}}):
            self.assertTrue(is_allowed(finding))


class SummarizeTests(SimpleTestCase):
    def _summarize(self, findings):
        return summarize(findings, stream=io.StringIO())

    def test_counts_blocking_sites(self):
        findings = [
            _finding(CROSS_ORG, ["apps/a.py::f:1"]),
            _finding(CROSS_TIME, ["apps/a.py::f:1"]),
            _finding(CROSS_ORG, ["apps/b.py::g:1"], runtime_pruned=True),
            _finding(CROSS_ORG, ["apps/c.py::h:1"], runtime_pruned=None),
        ]
        # a (both kinds, one site) and c (unverified) block; b is advisory.
        self.assertEqual(self._summarize(findings), 2)

    def test_allowlisted_hits_do_not_decide_the_verdict(self):
        findings = [
            _finding(CROSS_ORG, ["apps/a.py::f:1", "apps/ok.py::approved:1"]),
            _finding(CROSS_ORG, ["apps/a.py::f:1", "apps/other.py::caller:1"], True),
        ]
        with mock.patch.dict(ALLOWLIST, {"apps/ok.py::approved": {CROSS_ORG: "r"}}):
            self.assertEqual(self._summarize(findings), 0)

    def test_nothing_found(self):
        self.assertEqual(self._summarize([]), 0)


class CallChainTests(SimpleTestCase):
    def test_queries_from_test_code_are_ignored(self):
        self.assertIsNone(_call_chain())


# Unpruned by the planner (the org comes from a join), so the guard examines it,
# and a write, so re-running it anywhere but a rolled-back savepoint shows.
_BUMP = (
    "UPDATE issue_events_issueindex si SET count = si.count + 1 "
    "FROM unnest(%s::bigint[], %s::int[]) AS v(issue_id, org_id) "
    "WHERE si.issue_id = v.issue_id AND si.organization_id = v.org_id"
)


def _guard():
    guard = PartitionGuard(Path(tempfile.mkdtemp()) / "report.jsonl")
    # The guard ignores queries from test code; treat this one as app code.
    guard.call_chain = lambda: ["apps/example.py::bump:1"]
    return guard


class GuardLeavesNoWriteAutocommitTests(TransactionTestCase):
    async def test_async_autocommit(self):
        issue = await baker.amake("issue_events.Issue")
        leaf = await IssueIndex.objects.aget(issue_id=issue.id)
        before = leaf.count
        guard = _guard()
        async with await async_connections["default"].cursor() as cursor:
            await guard.check_async(cursor, _BUMP, [[issue.id], [leaf.organization_id]])
        await leaf.arefresh_from_db()
        self.assertEqual(leaf.count, before)
        self.assertTrue(guard.report_path.exists(), "the guard never examined it")


class GuardLeavesNoWriteInTransactionTests(TestCase):
    def test_sync_in_transaction(self):
        issue = baker.make("issue_events.Issue")
        leaf = IssueIndex.objects.get(issue_id=issue.id)
        before = leaf.count
        guard = _guard()
        with connection.cursor() as cursor:
            guard.check_sync(cursor, _BUMP, [[issue.id], [leaf.organization_id]])
        leaf.refresh_from_db()
        self.assertEqual(leaf.count, before)
        self.assertTrue(guard.report_path.exists(), "the guard never examined it")
