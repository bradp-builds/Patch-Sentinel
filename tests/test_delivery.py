"""Regression tests for ratelimit."""

import io
import json
import sqlite3
import tempfile
import unittest
import urllib.error
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import patch_sentinel as app
from tests.support import CONFIG, CVE, NOW, OTHER_CVE, WEBHOOK, archive, record


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.db = app.Database(":memory:", now=NOW)
        self.addCleanup(self.db.close)
        self.elapsed = 0.0
        self.sleeps = []
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch.object(app.time, "monotonic", side_effect=lambda: self.elapsed))
        stack.enter_context(patch.object(app.time, "sleep", side_effect=self.sleep))
        stack.enter_context(patch.object(app, "logger"))

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.elapsed += seconds

    def deliver(self, outcomes, now=NOW):
        summary = app.RunSummary()
        with patch.object(app, "send_notification", side_effect=outcomes) as send:
            app.deliver_pending(CONFIG, self.db, now, summary)
        return summary, send

    def test_download_time_is_included_in_persisted_cooldown(self):
        def fetch(url):
            self.elapsed += 1
            return archive(record())

        with (
            patch.object(app, "fetch_url", side_effect=fetch),
            patch.object(
                app, "send_notification", return_value=app.DeliveryResult(False, True, 3600)
            ),
        ):
            app.run_pipeline(CONFIG, self.db, now=NOW)
        self.assertAlmostEqual((self.db.delivery_not_before() - NOW).total_seconds(), 3624.05)

    def test_invalid_server_delays_are_ignored(self):
        for value in (None, "oops", "nan", "inf", -1, True, 10**1000):
            with self.subTest(value=value):
                self.assertIsNone(app.delay_seconds(value))

    def test_short_429_waits_and_retries_without_losing_alert(self):
        self.db.queue(CVE, record(), NOW)
        summary, send = self.deliver([app.DeliveryResult(False, True, 2), app.DeliveryResult(True)])
        self.assertEqual(send.call_count, 2)
        self.assertAlmostEqual(sum(self.sleeps), 2.05)
        self.assertEqual(summary.sent, 1)
        self.assertEqual(summary.exit_code, 0)
        self.assertTrue(self.db.has_notified(CVE))

    def test_successful_response_paces_next_notification(self):
        self.db.queue(CVE, record(), NOW)
        self.db.queue(OTHER_CVE, record(cve_id=OTHER_CVE), NOW)
        summary, send = self.deliver(
            [app.DeliveryResult(True, retry_after=2), app.DeliveryResult(True)]
        )
        self.assertEqual(send.call_count, 2)
        self.assertAlmostEqual(sum(self.sleeps), 2.05)
        self.assertEqual(summary.sent, 2)

    def test_long_cooldown_is_persisted_and_next_run_does_not_send_early(self):
        self.db.queue(CVE, record(), NOW)
        summary, send = self.deliver([app.DeliveryResult(False, True, 3600)])
        send.assert_called_once()
        self.assertEqual(self.sleeps, [])
        self.assertEqual(summary.pending, 1)
        self.assertGreater(self.db.delivery_not_before(), NOW + timedelta(hours=1))
        summary, send = self.deliver([], now=NOW + timedelta(minutes=10))
        send.assert_not_called()
        self.assertEqual(summary.pending, 1)
        summary, send = self.deliver([app.DeliveryResult(True)], now=NOW + timedelta(hours=2))
        send.assert_called_once()
        self.assertEqual(summary.sent, 1)

    def test_repeated_429_retries_are_bounded(self):
        self.db.queue(CVE, record(), NOW)
        summary, send = self.deliver([app.DeliveryResult(False, True, 0)] * 4)
        self.assertEqual(send.call_count, 4)
        self.assertEqual(summary.pending, 1)
        self.assertEqual(summary.errors, 1)

    def test_delivery_budget_preserves_remainder_and_caps_each_sleep(self):
        self.db.queue(CVE, record(), NOW)
        summary, send = self.deliver([app.DeliveryResult(False, True, 150)] * 2)
        self.assertEqual(send.call_count, 2)
        self.assertLess(sum(self.sleeps), app.DELIVERY_BUDGET_SECONDS)
        self.assertTrue(all(delay <= 60 for delay in self.sleeps))
        self.assertEqual(summary.pending, 1)

    def test_queued_alert_can_be_delivered_after_publication_window(self):
        self.db.queue(CVE, record(age=25), NOW - timedelta(hours=2))
        summary, send = self.deliver([app.DeliveryResult(True)])
        send.assert_called_once()
        self.assertEqual(summary.sent, 1)

    def test_updating_pending_alert_does_not_extend_deadline(self):
        queued = NOW - timedelta(hours=23)
        self.db.queue(CVE, record(age=24), queued)
        self.db.queue(CVE, record(age=24, score=9), NOW)
        self.assertEqual(datetime.fromisoformat(self.db.pending()[0][2]), queued)
        summary, send = self.deliver([], now=NOW + timedelta(hours=1))
        send.assert_not_called()
        self.assertEqual(summary.expired, 1)
        self.assertEqual(summary.exit_code, 1)
        self.assertEqual(self.db.pending(), [])

    def test_expired_alerts_are_cleaned_even_when_first_delivery_stops_batch(self):
        self.db.queue(CVE, record(), NOW)
        self.db.queue(OTHER_CVE, record(cve_id=OTHER_CVE), NOW - timedelta(hours=24))
        summary, send = self.deliver([app.DeliveryResult(False, True)])
        send.assert_called_once()
        self.assertEqual(summary.expired, 1)
        self.assertEqual(summary.pending, 1)

    def test_unknown_retry_timing_stops_without_busy_retry(self):
        self.db.queue(CVE, record(), NOW)
        summary, send = self.deliver([app.DeliveryResult(False, True)])
        send.assert_called_once()
        self.assertEqual(self.sleeps, [])
        self.assertEqual(summary.pending, 1)

    def test_rate_limit_header_and_body_parsing(self):
        config = replace(CONFIG, test_mode=False, webhook_url=WEBHOOK)
        for headers, body, expected in (
            ({"Retry-After": "1.25"}, b"{}", 1.25),
            ({}, b'{"retry_after": 2.5}', 2.5),
            ({"Retry-After": "nan"}, b'{"retry_after": 3}', 3),
            ({}, b"not JSON", None),
            ({}, b'{"retry_after": -1}', None),
        ):
            error = urllib.error.HTTPError(WEBHOOK, 429, "rate limited", headers, io.BytesIO(body))
            with (
                self.subTest(headers=headers, body=body),
                patch.object(app.urllib.request, "urlopen", side_effect=error),
            ):
                result = app.send_notification(config, app.parse_cve(CVE, record()), "Linux")
            self.assertFalse(result.success)
            self.assertTrue(result.stop_batch)
            self.assertEqual(result.retry_after, expected)
            self.assertTrue(error.closed)

    def test_successful_response_reads_remaining_and_reset_headers(self):
        config = replace(CONFIG, test_mode=False, webhook_url=WEBHOOK)
        with patch.object(app.urllib.request, "urlopen") as request:
            request.return_value.__enter__.return_value.headers = {
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset-After": "0.75",
            }
            result = app.send_notification(config, app.parse_cve(CVE, record()), "Linux")
        self.assertTrue(result.success)
        self.assertEqual(result.retry_after, 0.75)

    def test_legacy_queue_migration_sets_deadline_once_and_preserves_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sqlite")
            connection = sqlite3.connect(path)
            with connection:
                connection.execute(
                    "CREATE TABLE pending_notifications (cve_id TEXT PRIMARY KEY, record TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO pending_notifications VALUES (?, ?)", (CVE, json.dumps(record()))
                )
            connection.close()
            with app.Database(path, now=NOW) as db:
                self.assertEqual(datetime.fromisoformat(db.pending()[0][2]), NOW)
                db.defer_delivery(NOW + timedelta(minutes=10))
            with app.Database(path, now=NOW + timedelta(hours=1)) as db:
                self.assertEqual(datetime.fromisoformat(db.pending()[0][2]), NOW)
                self.assertEqual(db.delivery_not_before(), NOW + timedelta(minutes=10))
