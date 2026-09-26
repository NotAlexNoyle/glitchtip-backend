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
            from django.db import connections

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
            tables = [
                "issue_events_issueevent",
                "issue_events_issueaggregate",
                "issue_events_issuetag",
                "logs_logevent",
                "performance_spanstaging",
                "uptime_monitorcheck",
                "projects_issueeventprojecthourlystatistic",
                "projects_transactioneventprojecthourlystatistic",
                "projects_logprojecthourlystatistic",
                "uptime_uptimecheckhourlystatistic",
            ]

            with connections[using].cursor() as cursor:
                for table in tables:
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
        from django.db import connections as sync_connections

        for entry in old_config or []:
            try:
                wrapper = entry[0]
                test_db = wrapper.settings_dict["NAME"]
                with sync_connections[wrapper.alias].cursor() as cursor:
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
            _partition_guard.current_test = test.id()
        super().startTest(test)


class IntegrationTextTestRunner(TextTestRunner):
    resultclass = IntegrationTextTestResult


_partition_guard = None

# Partitioned tables and how far back to create history for them. Mirrors the
# tables maintain_partitions keeps; a partitioned table missing from here fails
# the run so the guard never silently judges a table with no history.
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
    distinguishable from a scan of all of them; and two weeks of past time
    partitions, so a time-bounded lookup is distinguishable from an unbounded
    one. ``GLITCHTIP_PARTITION_GUARD=report`` prints findings without failing;
    ``=off`` keeps the layout but skips the guard.
    """

    test_runner = IntegrationTextTestRunner
    hash_buckets = 16

    def setup_test_environment(self, **kwargs):
        global _partition_guard
        super().setup_test_environment(**kwargs)
        if os.environ.get("GLITCHTIP_PARTITION_GUARD") == "off":
            return
        report = Path(
            os.environ.get("GLITCHTIP_PARTITION_GUARD_REPORT", "partition_guard.jsonl")
        )
        _partition_guard = PartitionGuard(report.resolve())
        _partition_guard.install()

    def teardown_test_environment(self, **kwargs):
        if _partition_guard is not None:
            _partition_guard.uninstall()
        super().teardown_test_environment(**kwargs)

    def setup_databases(self, **kwargs):
        settings.PARTITION_HASH_BUCKETS = self.hash_buckets
        return super().setup_databases(**kwargs)

    def prepare_partitions(self, using):
        with connections[using].cursor() as cursor:
            cursor.execute(
                "SELECT c.relname FROM pg_partitioned_table pt "
                "JOIN pg_class c ON c.oid = pt.partrelid "
                "WHERE NOT c.relispartition AND pt.partstrat = 'r'"
            )
            range_tables = {row[0] for row in cursor.fetchall()}
        missing = range_tables - _HISTORY.keys()
        if missing:
            raise RuntimeError(
                f"IntegrationTestRunner has no history spec for {sorted(missing)}"
            )

        manager = PartitionManager(db_connection=using)
        today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        monday = today - timedelta(days=today.weekday())
        for table, (interval, key_type, periods) in _HISTORY.items():
            if table not in range_tables:
                continue
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
        blocking = summarize(load_findings(_partition_guard.report_path))
        if os.environ.get("GLITCHTIP_PARTITION_GUARD") == "report":
            return failures
        if blocking:
            sys.stderr.write(
                f"\nPartition guard: {blocking} unpruned call site(s) -- failing.\n"
            )
        return failures + blocking
