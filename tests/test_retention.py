"""GFS retention policy arithmetic."""

from __future__ import annotations

import datetime
import unittest

from tests import __doc__ as _tests_package  # noqa: F401

from haven.errors import UsageError
from haven.retention import RetentionPolicy, select_keep


def at(year: int, month: int, day: int, hour: int = 3) -> float:
    return datetime.datetime(year, month, day, hour, tzinfo=datetime.timezone.utc).timestamp()


def snaps(*moments: float) -> list[dict]:
    return [
        {"id": f"20260101T000000Z-{index:08x}", "created": moment}
        for index, moment in enumerate(moments)
    ]


class RetentionTests(unittest.TestCase):
    def test_keep_last_only(self):
        policy = RetentionPolicy(keep_last=2, keep_daily=0, keep_weekly=0, keep_monthly=0)
        items = snaps(at(2026, 1, 1), at(2026, 1, 2), at(2026, 1, 3))
        keep, drop = select_keep(items, policy)
        self.assertEqual(keep, {items[2]["id"], items[1]["id"]})
        self.assertEqual(drop, {items[0]["id"]})

    def test_keep_daily_picks_newest_per_day(self):
        policy = RetentionPolicy(keep_last=0, keep_daily=3, keep_weekly=0, keep_monthly=0)
        items = snaps(
            at(2026, 1, 1, 1), at(2026, 1, 1, 12),  # two on Jan 1
            at(2026, 1, 2), at(2026, 1, 3), at(2026, 1, 4),
        )
        keep, drop = select_keep(items, policy)
        self.assertEqual(keep, {items[2]["id"], items[3]["id"], items[4]["id"]})
        self.assertEqual(len(drop), 2)

    def test_keep_weekly_and_monthly(self):
        policy = RetentionPolicy(keep_last=0, keep_daily=0, keep_weekly=2, keep_monthly=1)
        items = snaps(
            at(2025, 11, 20), at(2025, 12, 2), at(2025, 12, 10),
            at(2026, 1, 7), at(2026, 1, 20),
        )
        keep, _drop = select_keep(items, policy)
        # newest month (Jan 2026) -> keep the newest Jan snapshot (Jan 20)
        self.assertIn(items[4]["id"], keep)
        # two newest ISO weeks: Jan 20 and Jan 7
        self.assertIn(items[3]["id"], keep)
        self.assertEqual(len(keep), 2)

    def test_keep_last_overrides_age(self):
        policy = RetentionPolicy(keep_last=1, keep_daily=1, keep_weekly=0, keep_monthly=0)
        items = snaps(at(2020, 1, 1), at(2026, 1, 1))
        keep, _ = select_keep(items, policy)
        self.assertIn(items[1]["id"], keep)

    def test_keep_within_days(self):
        policy = RetentionPolicy(keep_last=1, keep_daily=1, keep_weekly=0, keep_monthly=0, keep_within_days=2)
        items = snaps(at(2026, 1, 1), at(2026, 1, 9), at(2026, 1, 10))
        keep, _ = select_keep(items, policy)
        self.assertEqual(keep, {items[2]["id"], items[1]["id"]})

    def test_iso_strings_accepted(self):
        policy = RetentionPolicy(keep_last=1, keep_daily=0, keep_weekly=0, keep_monthly=0)
        items = [
            {"id": "a", "created": "2026-01-01T03:00:00Z"},
            {"id": "b", "created": "2026-01-02T03:00:00Z"},
        ]
        keep, drop = select_keep(items, policy)
        self.assertEqual(keep, {"b"})
        self.assertEqual(drop, {"a"})

    def test_everything_kept_when_policy_is_generous(self):
        policy = RetentionPolicy(keep_last=10, keep_daily=10, keep_weekly=10, keep_monthly=10)
        items = snaps(at(2026, 1, 1), at(2026, 1, 2))
        keep, drop = select_keep(items, policy)
        self.assertEqual(len(keep), 2)
        self.assertEqual(drop, set())

    def test_empty_policy_rejected(self):
        with self.assertRaises(UsageError):
            RetentionPolicy(keep_last=0, keep_daily=0, keep_weekly=0, keep_monthly=0)

    def test_negative_rejected(self):
        with self.assertRaises(UsageError):
            RetentionPolicy(keep_last=-1)

    def test_round_trip_json(self):
        policy = RetentionPolicy(keep_last=2, keep_daily=5, keep_weekly=3, keep_monthly=6, keep_yearly=1)
        restored = RetentionPolicy.from_json(policy.to_json())
        self.assertEqual(restored.to_json(), policy.to_json())
        with self.assertRaises(UsageError):
            RetentionPolicy.from_json({"keep_minutes": 3})

    def test_describe(self):
        self.assertIn("3 last", RetentionPolicy().describe())


if __name__ == "__main__":
    unittest.main()
