import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import time
from unittest.runner import TextTestResult, TextTestRunner

from django.conf import settings
from django.db import connections
from django.test.runner import DiscoverRunner

from glitchtip.partition_manager import PartitionManager
from glitchtip.test_utils.partition_guard import (
    PartitionGuard,
    load_findings,
    summarize,
)


class TimedTextTestResult(TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clocks = {}

    def startTest(self, test):
        self.clocks[test] = time()
        super(TextTestResult, self).startTest(test)
        if self.showAll:
            self.stream.write(self.getDescription(test))
            self.stream.write(" ... ")
            self.stream.flush()

    def addSuccess(self, test):
        super(TextTestResult, self).addSuccess(test)
        if self.showAll:
            self.stream.writeln("runtime (%.6fs)" % (time() - self.clocks[test]))
        elif self.dots:
            self.stream.write(".")
            self.stream.flush()


class TimedTextTestRunner(TextTestRunner):
    resultclass = TimedTextTestResult


def _range_partitioned_tables(cursor) -> set[str]:
    """Top-level RANGE-partitioned tables: the ones that take time partitions
    and, in tests, a DEFAULT partition."""
    cursor.execute(
        "SELECT c.relname FROM pg_partitioned_table pt "
        "JOIN pg_class c ON c.oid = pt.partrelid "
        "WHERE NOT c.relispartition AND pt.partstrat = 'r'"
    )
    return {row[0] for row in cursor.fetchall()}


class TimedTestRunner(DiscoverRunner):
    """To view timings, use ./manage.py test -v 2"""

    test_runner = TimedTextTestRunner

    def prepare_partitions(self, using):
        """Hook for runners that need a different partition layout. Runs after
        migrations, before the DEFAULT partitions are attached."""

    def setup_databases(self, **kwargs):
        from django.db.models.signals import post_migrate

        # post_migrate fires once per app; prepare each database only once,
        # before its DEFAULT partitions exist.
        prepared = set()

        def create_test_partitions(sender, **kwargs):
            using = kwargs.get("using")
            if not using:
                return

            if using not in prepared:
                prepared.add(using)
                self.prepare_partitions(using)

            # DEFAULT partitions are used here intentionally for tests.
            # In production, DEFAULT partitions must never be used (see AGENTS.md)
            # because they silently absorb rows and block nested RANGE->HASH
            # partition creation. In tests, they're safe: they catch all data
            # regardless of date, and PostgreSQL correctly routes rows to more
            # specific partitions when tests create their own.
            with connections[using].cursor() as cursor:
                for table in _range_partitioned_tables(cursor):
                    cursor.execute(
                        f"CREATE TABLE IF NOT EXISTS {table}_default "
                        f"PARTITION OF {table} DEFAULT"
                    )

        post_migrate.connect(create_test_partitions)
        try:
            result = super().setup_databases(**kwargs)
        finally:
            post_migrate.disconnect(create_test_partitions)
        return result

    def teardown_databases(self, old_config, **kwargs):
        # ``psycopg.AsyncConnection`` can't close synchronously from
        # ``__del__``, so async-backend connections opened in tasks that
        # have since ended still hold the socket open. Forcibly terminate
        # them so ``DROP DATABASE`` doesn't fail with "being accessed by
        # other users".
        for entry in old_config or []:
            try:
                wrapper = entry[0]
                test_db = wrapper.settings_dict["NAME"]
                with connections[wrapper.alias].cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = %s AND pid <> pg_backend_pid()",
                        [test_db],
                    )
            except Exception:
                # Don't let teardown failures mask the real test result.
                pass
        return super().teardown_databases(old_config, **kwargs)


class IntegrationTextTestResult(TimedTextTestResult):
    def startTest(self, test):
        if _partition_guard is not None:
            _partition_guard.start_test(test.id())
        super().startTest(test)


class IntegrationTextTestRunner(TimedTextTestRunner):
    resultclass = IntegrationTextTestResult


# The result class has no handle on the runner, so the guard lives here.
_partition_guard: PartitionGuard | None = None

# How much history to create for each RANGE-partitioned table: the intervals
# maintain_partitions uses, reaching back further than it keeps ahead. Every
# such table must be listed and every entry must exist, so the guard never
# judges a table without history and this cannot go stale unnoticed.
_HISTORY = {
    # table: (interval, key_type, periods back)
    "issue_events_issueevent": ("DAY", "uuid7", 14),
    "logs_logevent": ("DAY", "uuid7", 14),
    "performance_spanstaging": ("DAY", "uuid7", 14),
    "uptime_monitorcheck": ("WEEK", "uuid7", 3),
    "issue_events_issueaggregate": ("WEEK", "datetime", 3),
    "issue_events_issuetag": ("WEEK", "datetime", 3),
    "projects_issueeventprojecthourlystatistic": ("WEEK", "datetime", 3),
    "projects_transactioneventprojecthourlystatistic": ("WEEK", "datetime", 3),
    "projects_logprojecthourlystatistic": ("WEEK", "datetime", 3),
    "uptime_uptimecheckhourlystatistic": ("WEEK", "datetime", 3),
}


class IntegrationTestRunner(TimedTestRunner):
    """Runs the suite against a production-shaped partition layout with the
    partition pruning guard installed. CI only -- see the ``test-integration``
    job.

    The layout differs from the unit run in two ways that matter to the guard:
    16 hash buckets instead of 2, so a batch touching a few organizations is
    distinguishable from a scan of all of them; and past time partitions (two
    weeks of daily, three of weekly), so a time-bounded lookup is
    distinguishable from an unbounded one. ``GLITCHTIP_PARTITION_GUARD=report``
    prints findings without failing; ``=off`` keeps the layout but skips the
    guard.
    """

    test_runner = IntegrationTextTestRunner
    hash_buckets = 16

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Parallel workers set themselves up without this runner's hooks: no
        # guard, and the default bucket count against a 16-bucket clone.
        if self.parallel > 1:
            raise ValueError("IntegrationTestRunner does not support --parallel")

    def setup_databases(self, **kwargs):
        # Set here rather than in the CI job so a local run gets the same
        # layout; PartitionManager reads it whenever it creates partitions.
        settings.PARTITION_HASH_BUCKETS = self.hash_buckets
        result = super().setup_databases(**kwargs)
        # Installed only now, so migrations are neither checked nor used to
        # read the partition layout.
        global _partition_guard
        if os.environ.get("GLITCHTIP_PARTITION_GUARD") != "off":
            report = Path(
                os.environ.get(
                    "GLITCHTIP_PARTITION_GUARD_REPORT", "partition_guard.jsonl"
                )
            )
            _partition_guard = PartitionGuard(report.resolve())
            _partition_guard.install()
        return result

    def teardown_databases(self, old_config, **kwargs):
        if _partition_guard is not None:
            _partition_guard.uninstall()
        return super().teardown_databases(old_config, **kwargs)

    def prepare_partitions(self, using):
        with connections[using].cursor() as cursor:
            range_tables = _range_partitioned_tables(cursor)
        if range_tables != _HISTORY.keys():
            raise RuntimeError(
                "IntegrationTestRunner history is out of date: "
                f"missing {sorted(range_tables - _HISTORY.keys())}, "
                f"stale {sorted(_HISTORY.keys() - range_tables)}"
            )

        manager = PartitionManager(db_connection=using)
        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        monday = today - timedelta(days=today.weekday())
        for table, (interval, key_type, periods) in _HISTORY.items():
            end = today if interval == "DAY" else monday
            step = timedelta(days=1) if interval == "DAY" else timedelta(weeks=1)
            manager.create_partitions_for_date_range(
                parent_table=table,
                start_date=end - step * periods,
                end_date=end,
                partition_interval=interval,
                hash_column="organization_id",
                key_type=key_type,
            )

    def suite_result(self, suite, result, **kwargs):
        failures = super().suite_result(suite, result, **kwargs)
        if _partition_guard is None:
            return failures
        blocking = summarize(
            load_findings(_partition_guard.report_path), _partition_guard.errors
        )
        if os.environ.get("GLITCHTIP_PARTITION_GUARD") == "report":
            return failures
        if blocking:
            sys.stderr.write(
                f"\nPartition guard: {blocking} unpruned call site(s) -- failing.\n"
            )
        return failures + blocking
