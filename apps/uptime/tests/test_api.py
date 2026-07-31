from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from freezegun import freeze_time
from model_bakery import baker

from apps.uptime import api as uptime_api
from apps.uptime.api import _check_window
from apps.uptime.models import Monitor, MonitorCheck
from glitchtip.partition_manager import PartitionManager
from glitchtip.test_utils.test_case import GlitchTestCase


class UptimeAPITestCase(GlitchTestCase):
    @classmethod
    def setUpTestData(cls):
        cls.create_user()
        cls.list_url = reverse(
            "api:list_monitors",
            args=[cls.organization.slug],
        )

    def setUp(self):
        self.client.force_login(self.user)
        self.async_client.force_login(self.user)

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_list(self, mocked):
        monitor = await baker.amake(
            "uptime.Monitor", organization=self.organization, url="http://example.com"
        )
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=False,
            start_check="2021-09-19T15:39:31Z",
        )
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=True,
            is_change=True,
            start_check="2021-09-19T15:40:31Z",
        )
        monitor.cached_is_up = True
        monitor.cached_last_change = parse_datetime("2021-09-19T15:40:31Z")
        await monitor.asave(update_fields=["cached_is_up", "cached_last_change"])
        res = await self.async_client.get(self.list_url)
        self.assertContains(res, monitor.name)
        data = res.json()
        self.assertEqual(data[0]["isUp"], True)
        self.assertEqual(data[0]["lastChange"], "2021-09-19T15:40:31Z")

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_list_aggregation(self, _):
        """Test up and down event aggregations"""
        monitor = await baker.amake(
            "uptime.Monitor", organization=self.organization, url="http://example.com"
        )
        start_time = timezone.now()
        # Make 100 events, 50 up and then 50 up and down every minute
        for i in range(99):
            is_up = i % 2
            if i < 50:
                is_up = True
            current_time = start_time + timezone.timedelta(minutes=i)
            with freeze_time(current_time):
                await baker.amake(
                    "uptime.MonitorCheck",
                    monitor=monitor,
                    organization=monitor.organization,
                    is_up=is_up,
                    start_check=current_time,
                )
        with freeze_time(current_time):
            res = await self.async_client.get(self.list_url)
        self.assertEqual(len(res.json()[0]["checks"]), 60)

    # Kept synchronous: relies on captureOnCommitCallbacks + a sync mock
    # assertion. on_commit callbacks fired by the async request run on the
    # async DB connection, which the sync capture context cannot observe.
    @mock.patch("apps.uptime.tasks.perform_checks")
    def test_create_http_monitor(self, mocked):
        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "https://www.google.com",
            "expectedStatus": 200,
            "expectedBody": "",
            "interval": 60,
            "project": str(self.project.pk),
            "timeout": 25,
        }
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(self.list_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        monitor = Monitor.objects.all().first()
        self.assertEqual(monitor.name, data["name"])
        self.assertEqual(monitor.timeout, data["timeout"])
        self.assertEqual(monitor.organization, self.organization)
        self.assertEqual(monitor.project, self.project)
        # Defaults to the current behavior (alert on first failure) when omitted
        self.assertEqual(monitor.confirmation_threshold, 1)
        mocked.enqueue.assert_called_once()

    # Kept synchronous: see note on test_create_http_monitor.
    @mock.patch("apps.uptime.tasks.perform_checks")
    def test_create_monitor_confirmation_threshold(self, mocked):
        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "https://www.google.com",
            "expectedStatus": 200,
            "expectedBody": "",
            "interval": 60,
            "project": str(self.project.pk),
            "timeout": 25,
            "confirmationThreshold": 3,
        }
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(self.list_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["confirmationThreshold"], 3)
        monitor = Monitor.objects.get()
        self.assertEqual(monitor.confirmation_threshold, 3)

    @mock.patch("apps.uptime.tasks.perform_checks")
    def test_create_port_monitor(self, mocked):
        """Port monitor URLs should be converted to domain:port format, with protocol removed"""
        data = {
            "monitorType": "TCP Port",
            "name": "Test",
            "url": "http://example.com:80",
            "expectedStatus": None,
            "expectedBody": "",
            "timeout": None,
            "interval": 60,
        }
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(self.list_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        monitor = Monitor.objects.all().first()
        self.assertEqual(monitor.url, "example.com:80")
        mocked.enqueue.assert_called_once()

    async def test_create_port_monitor_validation(self):
        """Port monitor URLs should be converted to domain:port format, with protocol removed"""
        data = {
            "monitorType": "TCP Port",
            "name": "Test",
            "url": "example:80:",
            "expectedStatus": None,
            "expectedBody": "",
            "timeout": None,
            "interval": 60,
        }
        res = await self.async_client.post(
            self.list_url, data, content_type="application/json"
        )
        self.assertEqual(res.status_code, 422)

    async def test_create_invalid(self):
        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "foo:80:",
            "interval": 60,
            "expectedStatus": 200,
            "expectedBody": "",
            "timeout": None,
            "project": self.project.pk,
        }
        res = await self.async_client.post(
            self.list_url, data, content_type="application/json"
        )
        self.assertEqual(res.status_code, 422)

        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "https://www.google.com",
            "expectedStatus": 200,
            "expectedBody": "",
            "interval": 60,
            "project": self.project.pk,
            "timeout": 999,
        }
        res = await self.async_client.post(
            self.list_url, data, content_type="application/json"
        )
        self.assertEqual(res.status_code, 422)

    # Kept synchronous: see note on test_create_http_monitor.
    @mock.patch("apps.uptime.tasks.perform_checks")
    def test_create_max_interval(self, mocked):
        """A one-day interval (86400) is allowed by the validator and must not
        overflow the column (previously a smallint, max 32767)."""
        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "https://www.google.com",
            "expectedStatus": 200,
            "expectedBody": "",
            "interval": 86400,
            "project": str(self.project.pk),
            "timeout": 25,
        }
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(self.list_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        monitor = Monitor.objects.all().first()
        self.assertEqual(monitor.interval, 86400)

    def test_create_over_max_interval(self):
        """An interval above the 86400 ceiling must be rejected at the API
        layer (clean 4xx) rather than reaching the DB and raising a 500."""
        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "https://www.google.com",
            "expectedStatus": 200,
            "expectedBody": "",
            "interval": 86401,
            "project": str(self.project.pk),
            "timeout": 25,
        }
        res = self.client.post(self.list_url, data, content_type="application/json")
        self.assertEqual(res.status_code, 422)
        self.assertEqual(Monitor.objects.count(), 0)

    @mock.patch("apps.uptime.tasks.perform_checks")
    def test_create_expected_status(self, mocked):
        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "http://example.com",
            "expectedStatus": None,
            "expectedBody": "",
            "timeout": None,
            "interval": 60,
            "project": str(self.project.pk),
        }
        with self.captureOnCommitCallbacks(execute=True):
            res = self.client.post(self.list_url, data, content_type="application/json")
        mocked.enqueue.assert_called_once()
        self.assertEqual(res.status_code, 201)
        self.assertTrue(Monitor.objects.filter(expected_status=None).exists())

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_monitor_retrieve(self, _):
        """Test monitor details endpoint. Unlike the list view,
        checks here should include response time for the frontend graph"""
        environment = await baker.amake(
            "environments.Environment", organization=self.organization
        )

        monitor = await baker.amake(
            "uptime.Monitor",
            organization=self.organization,
            url="http://example.com",
            monitor_type="Heartbeat",
            environment=environment,
        )

        now = timezone.now()
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=False,
            is_change=True,
            start_check="2021-09-19T15:39:31Z",
        )
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=True,
            is_change=True,
            start_check=now,
        )
        monitor.cached_is_up = True
        monitor.cached_last_change = now
        await monitor.asave(update_fields=["cached_is_up", "cached_last_change"])

        url = reverse("api:get_monitor", args=[self.organization.slug, monitor.pk])
        res = await self.async_client.get(url)
        data = res.json()
        self.assertEqual(data["isUp"], True)
        self.assertEqual(parse_datetime(data["lastChange"]), now)
        self.assertEqual(data["environmentID"], environment.pk)
        self.assertIn("responseTime", data["checks"][0])

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_monitor_checks_list(self, _):
        monitor = await baker.amake(
            "uptime.Monitor",
            organization=self.organization,
            url="http://example.com",
        )
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=False,
            start_check="2021-09-19T15:39:31Z",
        )

        url = reverse(
            "api:list_monitor_checks", args=[self.organization.slug, monitor.pk]
        )

        res = await self.async_client.get(url)
        self.assertContains(res, "2021-09-19T15:39:31Z")

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_monitor_checks_is_change_baseline(self, _):
        """When all is_change=True records have been pruned (e.g. partition
        retention on a 100% uptime monitor), the is_change=true filter should
        still return at least one record — the most recent check should be
        marked as a baseline change."""
        monitor = await baker.amake(
            "uptime.Monitor",
            organization=self.organization,
            url="http://example.com",
        )
        # Simulate post-pruning state: only is_change=False checks remain
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=True,
            is_change=False,
            start_check="2021-09-19T15:39:31Z",
        )
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=True,
            is_change=False,
            start_check="2021-09-19T15:40:31Z",
        )

        url = reverse(
            "api:list_monitor_checks", args=[self.organization.slug, monitor.pk]
        )

        # Without filter, all checks are returned
        res = await self.async_client.get(url)
        self.assertEqual(len(res.json()), 2)

        # With is_change=true, should return nothing (no baseline yet)
        res = await self.async_client.get(url + "?is_change=true")
        self.assertEqual(len(res.json()), 0)

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_monitor_update(self, _):
        monitor = await baker.amake(
            "uptime.Monitor",
            organization=self.organization,
            url="http://example.com",
            interval="60",
            monitor_type="Ping",
            expected_status=None,
        )

        url = reverse("api:update_monitor", args=[self.organization.slug, monitor.pk])
        data = {
            "name": monitor.name,
            "url": "https://differentexample.com",
            "monitorType": "Ping",
            "interval": 60,
            "expectedBody": "",
            "expected_status": None,
            "timeout": 20,
            "project": str(self.project.id),
        }

        res = await self.async_client.put(url, data, content_type="application/json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["projectID"], str(self.project.id))
        self.assertEqual(res.json()["url"], "https://differentexample.com")

        data = {
            "name": monitor.name,
            "url": "https://differentexample.com",
            "monitorType": "GET",
            "interval": 60,
            "expectedBody": "test",
            "expected_status": None,
            "timeout": 20,
            "project": str(self.project.id),
        }

        res = await self.async_client.put(url, data, content_type="application/json")
        self.assertEqual(res.status_code, 422)

        data = {
            "name": monitor.name,
            "url": "https://differentexample.com",
            "monitorType": "GET",
            "interval": 60,
            "expectedBody": "",
            "expected_status": 422,
            "timeout": None,
            "project": str(self.project.id),
        }

        res = await self.async_client.put(url, data, content_type="application/json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["monitorType"], "GET")
        self.assertEqual(res.json()["expectedBody"], "")
        self.assertEqual(res.json()["timeout"], None)

    async def test_monitor_delete(self):
        monitor = await baker.amake(
            "uptime.Monitor",
            organization=self.organization,
            url="http://example.com",
            interval="60",
            monitor_type="Ping",
            expected_status=None,
        )
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=monitor.organization,
            is_up=False,
            start_check="2021-09-19T15:39:31Z",
        )

        url = reverse("api:delete_monitor", args=[self.organization.slug, monitor.pk])
        res = await self.async_client.delete(url)
        self.assertEqual(res.status_code, 204)
        self.assertEqual(await Monitor.objects.acount(), 0)
        self.assertEqual(await MonitorCheck.objects.acount(), 0)

        another_org = await baker.amake("organizations_ext.Organization")
        another_monitor = await baker.amake(
            "uptime.Monitor",
            organization=another_org,
            url="http://example.com",
            interval="60",
            monitor_type="Ping",
            expected_status=None,
        )

        url = reverse("api:delete_monitor", args=[another_org.slug, another_monitor.pk])
        res = await self.async_client.delete(url)
        self.assertEqual(res.status_code, 404)

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_list_isolation(self, _):
        """Users should only access monitors in their organization"""
        user2 = await baker.amake("users.user")
        org2 = await baker.amake("organizations_ext.Organization")
        await org2.aadd_user(user2)
        monitor1 = await baker.amake(
            "uptime.Monitor", url="http://example.com", organization=self.organization
        )
        monitor2 = await baker.amake(
            "uptime.Monitor", url="http://example.com", organization=org2
        )

        res = await self.async_client.get(self.list_url)
        self.assertContains(res, monitor1.name)
        self.assertNotContains(res, monitor2.name)

    async def test_create_isolation(self):
        """Users should only make monitors in their organization"""
        org2 = await baker.amake("organizations_ext.Organization")

        url = reverse("api:list_monitors", args=[org2.slug])
        data = {
            "monitorType": "Ping",
            "name": "Test",
            "url": "https://www.google.com",
            "expectedStatus": 200,
            "interval": 60,
            "project": self.project.pk,
        }
        res = await self.async_client.post(url, data)
        self.assertEqual(res.status_code, 400)


class CheckWindowTestCase(SimpleTestCase):
    """The partition-key window derived for each monitor.

    ``uptime_monitorcheck`` is partitioned by ``id`` (a UUIDv7), so bounding
    ``id`` from below is what prunes the daily partitions. The window must be
    wide enough to hold ``limit`` checks at the monitor's own interval —
    a window that is too narrow returns a short list and renders a
    partially-blank chart.
    """

    def window(self, interval: int, age_days: float, retention_days: int = 90):
        now = timezone.now()
        monitor = Monitor(interval=interval, created=now - timedelta(days=age_days))
        return _check_window(monitor, 60, now, timedelta(days=retention_days))

    def test_frequent_monitor_gets_narrowest_window(self):
        # 60 checks at 60s span an hour; the 1-day bucket is ample.
        self.assertEqual(self.window(interval=60, age_days=365), timedelta(days=1))

    def test_hourly_monitor_gets_wider_window(self):
        # 60 checks at 1h span 2.5 days, doubled for slack -> the 7-day bucket.
        self.assertEqual(self.window(interval=3600, age_days=365), timedelta(days=7))

    def test_daily_monitor_is_unbounded(self):
        # 60 daily checks span 60 days; with slack that exceeds retention, so no
        # bucket is narrower than the table and the bound would buy nothing.
        self.assertIsNone(self.window(interval=86400, age_days=365))

    def test_young_monitor_is_bounded_by_its_own_age(self):
        # A daily-interval monitor created an hour ago cannot hold checks older
        # than an hour, so it gets the narrowest window despite its interval.
        # This is what keeps pages containing new monitors off the full scan.
        self.assertEqual(self.window(interval=86400, age_days=0), timedelta(days=1))

    def test_window_never_exceeds_retention(self):
        # Nothing to prune when the whole table is one day wide.
        self.assertIsNone(self.window(interval=60, age_days=365, retention_days=1))


class MonitorCheckPartitionBoundTestCase(GlitchTestCase):
    """End-to-end behaviour of the bounded check fetch on ``/monitors/``."""

    # Days back that stale checks are written to. Kept small: each day needs its
    # own set of partitions created below.
    STALE_DAYS = 5

    @classmethod
    def setUpTestData(cls):
        cls.create_user()
        cls.list_url = reverse("api:list_monitors", args=[cls.organization.slug])
        # The test database only carries partitions from today forward. Backdated
        # checks need their own daily partitions, because the partition key is
        # the UUIDv7 ``id`` — minted at insert — not ``start_check``. Bounds must
        # land on day boundaries or they overlap today's existing partition.
        today = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        PartitionManager().create_partitions_for_date_range(
            parent_table="uptime_monitorcheck",
            start_date=today - timedelta(days=cls.STALE_DAYS + 2),
            end_date=today,
            partition_interval="DAY",
            hash_buckets=None,
            hash_column="organization_id",
            key_type="uuid7",
        )

    def setUp(self):
        self.async_client.force_login(self.user)

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_checks_older_than_window_are_still_returned(self, _):
        """Checks outside the interval-derived window must not be lost.

        A 60s-interval monitor gets the 1-day window, but one that stopped
        reporting a week ago has all of its checks outside it. The unbounded
        second pass has to find them, or a paused monitor silently renders an
        empty chart.
        """
        now = timezone.now()
        monitor = await baker.amake(
            "uptime.Monitor",
            organization=self.organization,
            url="http://example.com",
            interval=60,
        )
        # Age the monitor past its window, otherwise the window would cover its
        # whole lifetime and the second pass would correctly be skipped.
        monitor.created = now - timedelta(days=self.STALE_DAYS + 1)
        await monitor.asave(update_fields=["created"])

        stale = now - timedelta(days=self.STALE_DAYS)
        with freeze_time(stale):
            for _ in range(3):
                await baker.amake(
                    "uptime.MonitorCheck",
                    monitor=monitor,
                    organization=self.organization,
                    is_up=True,
                    start_check=stale,
                )

        res = await self.async_client.get(self.list_url)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()[0]["checks"]), 3)

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_young_monitor_needs_no_unbounded_pass(self, _):
        """A monitor younger than its window is never re-queried unbounded.

        New monitors always hold fewer than ``limit`` checks. Flooring the
        window at the creation timestamp makes a short result conclusive, which
        is what stops every page containing a new monitor from falling back to
        scanning all partitions.
        """
        monitor = await baker.amake(
            "uptime.Monitor",
            organization=self.organization,
            url="http://example.com",
            interval=60,
        )
        await baker.amake(
            "uptime.MonitorCheck",
            monitor=monitor,
            organization=self.organization,
            is_up=True,
        )

        with mock.patch.object(
            uptime_api,
            "fetch_checks_lateral",
            wraps=uptime_api.fetch_checks_lateral,
        ) as spy:
            res = await self.async_client.get(self.list_url)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()[0]["checks"]), 1)
        # One bounded query, and no unbounded retry.
        self.assertEqual(spy.call_count, 1)
        self.assertIsNotNone(spy.call_args.kwargs["min_id"])

    @mock.patch("apps.uptime.tasks.perform_checks")
    async def test_monitors_are_grouped_into_one_query_per_window(self, _):
        """Monitors needing different windows are batched, not queried per row.

        A page holding a 60s monitor and an hourly one needs two windows; it
        must cost two queries, not one per monitor.
        """
        for interval in (60, 60, 3600, 3600):
            monitor = await baker.amake(
                "uptime.Monitor",
                organization=self.organization,
                url="http://example.com",
                interval=interval,
            )
            monitor.created = timezone.now() - timedelta(days=self.STALE_DAYS + 1)
            await monitor.asave(update_fields=["created"])
            # 60 checks each, so no monitor is short and no retry is triggered.
            await MonitorCheck.objects.abulk_create(
                [
                    MonitorCheck(
                        monitor=monitor,
                        organization=self.organization,
                        is_up=True,
                        is_change=False,
                    )
                    for _ in range(60)
                ]
            )

        with mock.patch.object(
            uptime_api,
            "fetch_checks_lateral",
            wraps=uptime_api.fetch_checks_lateral,
        ) as spy:
            res = await self.async_client.get(self.list_url)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()), 4)
        self.assertEqual(spy.call_count, 2)
