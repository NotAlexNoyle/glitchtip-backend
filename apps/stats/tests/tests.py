from datetime import datetime, timedelta

from django.urls import reverse
from django.utils import timezone
from model_bakery import baker

from apps.projects.models import (
    IssueEventProjectHourlyStatistic,
    TransactionEventProjectHourlyStatistic,
)
from glitchtip.test_utils.test_case import GlitchTipTestCase


class StatsV2APITestCase(GlitchTipTestCase):
    def setUp(self):
        self.create_user_and_project()
        self.async_client.force_login(self.user)
        self.url = reverse("api:stats_v2", args=[self.organization.slug])

    async def test_get(self):
        await baker.amake("issue_events.IssueEvent", issue__project=self.project)
        start = timezone.now() - timezone.timedelta(hours=2)
        end = timezone.now()
        res = await self.async_client.get(
            self.url,
            {"category": "error", "start": start, "end": end, "field": "sum(quantity)"},
        )
        self.assertEqual(res.status_code, 200)

        response = res.json()
        self.assertIsInstance(response["intervals"], list)
        self.assertEqual(len(response["intervals"]), 4)
        self.assertIsInstance(
            datetime.fromisoformat(response["intervals"][0]), datetime
        )

    async def make_stat(
        self, date, count, project=None, model=IssueEventProjectHourlyStatistic
    ):
        project = project or self.project
        await model.objects.acreate(
            project=project,
            organization_id=project.organization_id,
            date=date,
            count=count,
        )

    async def get_series(self, start, end, interval, category="error"):
        res = await self.async_client.get(
            self.url,
            {
                "category": category,
                "start": start,
                "end": end,
                "interval": interval,
                "field": "sum(quantity)",
                "project": self.project.id,
            },
        )
        return res.json()

    async def test_daily_interval_counts_every_hour(self):
        day = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        day -= timedelta(days=2)
        for category, model in (
            ("error", IssueEventProjectHourlyStatistic),
            ("transaction", TransactionEventProjectHourlyStatistic),
        ):
            with self.subTest(category):
                for hour, count in ((0, 1), (5, 2), (23, 3)):
                    await self.make_stat(
                        day + timedelta(hours=hour), count, model=model
                    )

                data = await self.get_series(
                    day, day + timedelta(days=1), "1d", category
                )
                self.assertEqual(
                    data["groups"][0]["series"]["sum(quantity)"], [6, None]
                )

    async def test_minute_interval_counts_each_hour_once(self):
        hour = timezone.now().replace(minute=0, second=0, microsecond=0)
        hour -= timedelta(hours=2)
        await self.make_stat(hour, 4)

        # Starts an hour early: the old join spread the count over that hour
        start = hour - timedelta(hours=1)
        data = await self.get_series(start, hour + timedelta(minutes=30), "1m")
        series = data["groups"][0]["series"]["sum(quantity)"]
        self.assertEqual(sum(n or 0 for n in series), 4)
        self.assertEqual(series[60], 4)

    async def test_empty_hours_are_kept(self):
        start = timezone.now().replace(minute=0, second=0, microsecond=0)
        start -= timedelta(hours=6)
        other_project = await baker.amake(
            "projects.Project", organization=self.organization
        )
        await self.make_stat(start + timedelta(hours=1), 5, other_project)
        await self.make_stat(start + timedelta(hours=3), 4)

        data = await self.get_series(start, start + timedelta(hours=5), "1h")
        series = data["groups"][0]["series"]["sum(quantity)"]
        self.assertEqual(len(data["intervals"]), 7)
        self.assertEqual(series, [None, None, None, 4, None, None, None])
