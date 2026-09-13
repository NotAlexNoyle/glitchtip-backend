from django.conf import settings
from django.test import SimpleTestCase


class VtasksScheduleTests(SimpleTestCase):
    """Every scheduled task must use a schedule type the scheduler acts on.

    django-vtasks recognises a cron string or an integer number of seconds;
    any other type leaves the entry permanently not due, with no error and no
    log line. The throttle sweep was scheduled with a ``timedelta`` for a long
    time and never ran.
    """

    def test_every_schedule_is_a_cron_string_or_seconds(self):
        for name, entry in settings.VTASKS_SCHEDULE.items():
            with self.subTest(name):
                schedule = entry["schedule"]
                self.assertIsInstance(schedule, (str, int))
                self.assertNotIsInstance(schedule, bool)
                if isinstance(schedule, int):
                    self.assertGreater(schedule, 0)

    def test_throttle_sweep_is_scheduled(self):
        # Tests run with billing enabled and the sweep scheduled, so the
        # check above covers it.
        self.assertIn("check-all-organizations-throttle", settings.VTASKS_SCHEDULE)
