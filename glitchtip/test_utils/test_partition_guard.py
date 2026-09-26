from unittest import mock

from django.test import SimpleTestCase

from .partition_guard import (
    CROSS_ORG,
    CROSS_TIME,
    Finding,
    _PartitionTree,
    _relation_names,
    is_allowed,
)

ROOT = "events"
DAYS = ["events_d1", "events_d2", "events_d3"]
BUCKETS = 4


def _tree():
    rows = [(ROOT, None, "r", False), ("events_default", ROOT, None, True)]
    for day in DAYS:
        rows.append((day, ROOT, "h", False))
        for b in range(BUCKETS):
            rows.append((f"{day}_h{b}", day, None, False))
    rows += [("index", None, "h", False)]
    rows += [(f"index_h{b}", "index", None, False) for b in range(BUCKETS)]
    return _PartitionTree(rows)


def _kinds(tree, relations):
    return {(kind, table) for kind, table, _ in tree.analyze(set(relations))}


class PartitionTreeTests(SimpleTestCase):
    def test_fully_pruned(self):
        self.assertEqual(_kinds(_tree(), ["events_d2_h1"]), set())

    def test_some_buckets_some_days_is_fine(self):
        tree = _tree()
        rels = ["events_d1_h0", "events_d1_h3", "events_d2_h0", "events_default"]
        self.assertEqual(_kinds(tree, rels), set())

    def test_every_bucket_is_cross_org(self):
        rels = [f"events_d2_h{b}" for b in range(BUCKETS)]
        self.assertEqual(_kinds(_tree(), rels), {(CROSS_ORG, ROOT)})

    def test_every_day_is_cross_time(self):
        rels = [f"{day}_h1" for day in DAYS]
        self.assertEqual(_kinds(_tree(), rels), {(CROSS_TIME, ROOT)})

    def test_unpruned_is_both(self):
        rels = [f"{day}_h{b}" for day in DAYS for b in range(BUCKETS)]
        self.assertEqual(_kinds(_tree(), rels), {(CROSS_ORG, ROOT), (CROSS_TIME, ROOT)})

    def test_default_partition_is_ignored(self):
        rels = [f"{day}_h1" for day in DAYS[:2]] + ["events_default"]
        self.assertEqual(_kinds(_tree(), rels), set())

    def test_hash_only_table(self):
        tree = _tree()
        self.assertEqual(_kinds(tree, ["index_h2"]), set())
        rels = [f"index_h{b}" for b in range(BUCKETS)]
        self.assertEqual(_kinds(tree, rels), {(CROSS_ORG, "index")})

    def test_mentions_partitioned(self):
        tree = _tree()
        self.assertTrue(tree.mentions_partitioned('SELECT 1 FROM "events"'))
        self.assertFalse(tree.mentions_partitioned("SELECT 1 FROM projects"))

    def test_relation_names_walks_nested_plans(self):
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

    def test_relation_names_executed_only(self):
        plan = [
            {
                "Plan": {
                    "Actual Loops": 1,
                    "Plans": [
                        {"Relation Name": "events_d1_h0", "Actual Loops": 1},
                        {"Relation Name": "events_d1_h1", "Actual Loops": 0},
                    ],
                }
            }
        ]
        self.assertEqual(_relation_names(plan, executed=True), {"events_d1_h0"})


def _finding(kind, chain):
    return Finding(
        kind=kind,
        table=ROOT,
        detail="",
        runtime_pruned=False,
        site=chain[0],
        chain=chain,
        test="t",
        sql="",
    )


class AllowlistTests(SimpleTestCase):
    chain = ["apps/a/helpers.py::paginate:10", "apps/a/api.py::list_things:40"]

    def test_any_frame_in_chain_matches(self):
        entries = {"apps/a/api.py::list_things": {CROSS_TIME: "LIMIT on id"}}
        with mock.patch.dict("glitchtip.test_utils.partition_guard.ALLOWLIST", entries):
            self.assertTrue(is_allowed(_finding(CROSS_TIME, self.chain)))
            self.assertFalse(is_allowed(_finding(CROSS_ORG, self.chain)))

    def test_unlisted_site_is_not_allowed(self):
        entries = {"apps/b/api.py::other": {CROSS_TIME: "reason"}}
        with mock.patch.dict("glitchtip.test_utils.partition_guard.ALLOWLIST", entries):
            self.assertFalse(is_allowed(_finding(CROSS_TIME, self.chain)))
