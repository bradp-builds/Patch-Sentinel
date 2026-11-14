"""Regression tests for pipeline."""

import io
import unittest
import zipfile
from datetime import UTC, timedelta, timezone
from unittest.mock import patch

import patch_sentinel as app
from tests.support import CONFIG, CVE, NOW, OTHER_CVE, archive, record


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.db = app.Database(":memory:")
        self.addCleanup(self.db.close)
        logger = patch.object(app, "logger")
        logger.start()
        self.addCleanup(logger.stop)

    def test_release_slots_use_lookback_instead_of_a_fixed_hour_count(self):
        with patch.object(app, "LOOKBACK", timedelta(hours=2)):
            slots = list(app.release_slots(NOW))
        self.assertEqual([slot[1] for slot in slots], ["2026-11-13_1100Z", "2026-11-13_1200Z"])
        self.assertTrue(all(dt.tzinfo is UTC for dt, _ in slots))

    def test_release_slots_normalize_offsets_and_include_exact_boundary(self):
        local = NOW.replace(minute=0).astimezone(timezone(timedelta(hours=-5)))
        slots = list(app.release_slots(local))
        self.assertEqual(len(slots), 25)
        self.assertEqual(slots[0][0], NOW.replace(minute=0) - app.LOOKBACK)
        self.assertEqual(slots[-1][0], NOW.replace(minute=0))

    def test_release_slots_reject_naive_time(self):
        with self.assertRaises(ValueError):
            list(app.release_slots(NOW.replace(tzinfo=None)))

    def test_initial_downloads_are_bounded_to_24_hours(self):
        with patch.object(app, "fetch_url", return_value=None) as fetch:
            result = app.run_pipeline(CONFIG, self.db, now=NOW)
        self.assertEqual(fetch.call_count, 24)
        self.assertIn("2026-11-12_1300Z", fetch.call_args_list[0].args[0])
        self.assertIn("2026-11-13_1200Z", fetch.call_args_list[-1].args[0])
        self.assertEqual(result.exit_code, 0)

    def test_hour_boundary_includes_both_endpoints(self):
        with patch.object(app, "fetch_url", return_value=None) as fetch:
            app.run_pipeline(CONFIG, self.db, now=NOW.replace(minute=0))
        self.assertEqual(fetch.call_count, 25)

    def test_only_404_is_retired_after_later_success(self):
        outcomes = [None, app.FetchError("timeout")] + [archive(record())] * 22
        with patch.object(app, "fetch_url", side_effect=outcomes):
            result = app.run_pipeline(CONFIG, self.db, now=NOW)
        self.assertIn("2026-11-12_1300Z", self.db.processed_releases())
        self.assertNotIn("2026-11-12_1400Z", self.db.processed_releases())
        self.assertEqual(result.exit_code, 1)

    def test_trailing_404_remains_pending(self):
        with patch.object(app, "fetch_url", return_value=None):
            app.run_pipeline(CONFIG, self.db, now=NOW)
        self.assertEqual(self.db.processed_releases(), set())

    def test_previously_processed_later_release_retires_404(self):
        self.db.mark_processed("2026-11-13_1100Z", NOW)
        with patch.object(app, "fetch_url", return_value=None):
            app.run_pipeline(CONFIG, self.db, now=NOW)
        self.assertIn("2026-11-13_1000Z", self.db.processed_releases())
        self.assertNotIn("2026-11-13_1200Z", self.db.processed_releases())

    def test_failed_delivery_is_attempted_once_per_run_and_retried(self):
        with (
            patch.object(app, "fetch_url", return_value=archive(record())),
            patch.object(app, "send_notification", return_value=app.DeliveryResult(False)) as send,
        ):
            result = app.run_pipeline(CONFIG, self.db, now=NOW)
        send.assert_called_once()
        self.assertEqual(result.pending, 1)
        self.assertEqual(result.exit_code, 1)
        with (
            patch.object(app, "fetch_url") as fetch,
            patch.object(app, "send_notification", return_value=app.DeliveryResult(True)) as send,
        ):
            result = app.run_pipeline(CONFIG, self.db, now=NOW)
        fetch.assert_not_called()
        send.assert_called_once()
        self.assertTrue(self.db.has_notified(CVE))
        self.assertEqual(result.exit_code, 0)

    def test_later_qualifying_version_is_evaluated(self):
        summary = app.RunSummary()
        for score in (3, 9):
            app.process_zip_data(CONFIG, archive(record(score=score)), self.db, NOW, summary)
        with patch.object(app, "send_notification", return_value=app.DeliveryResult(True)) as send:
            app.deliver_pending(CONFIG, self.db, NOW, summary)
            app.deliver_pending(CONFIG, self.db, NOW, summary)
        send.assert_called_once()
        self.assertEqual(send.call_args.args[1].score, 9)

    def test_malformed_update_does_not_destroy_pending_alert(self):
        self.db.queue(CVE, record(), NOW)
        summary = app.RunSummary()
        app.process_zip_data(CONFIG, archive(None), self.db, NOW, summary)
        self.assertEqual(len(self.db.pending()), 1)
        self.assertEqual(summary.invalid_records, 1)

    def test_expired_pending_is_removed_without_delivery(self):
        self.db.queue(CVE, record(age=25), NOW - timedelta(hours=24))
        with patch.object(app, "send_notification") as send:
            app.deliver_pending(CONFIG, self.db, NOW, app.RunSummary())
        send.assert_not_called()
        self.assertEqual(self.db.pending(), [])

    def test_invalid_pending_entry_does_not_block_valid_delivery(self):
        self.db.queue(CVE, {}, NOW)
        self.db.queue(OTHER_CVE, record(cve_id=OTHER_CVE), NOW)
        summary = app.RunSummary()
        with patch.object(app, "send_notification", return_value=app.DeliveryResult(True)) as send:
            app.deliver_pending(CONFIG, self.db, NOW, summary)
        send.assert_called_once()
        self.assertEqual(summary.errors, 1)
        self.assertEqual(summary.pending, 0)

    def test_naive_clock_is_rejected(self):
        with self.assertRaises(ValueError):
            app.run_pipeline(CONFIG, self.db, now=NOW.replace(tzinfo=None))

    def test_rate_limit_stops_batch_and_preserves_remaining_work(self):
        self.db.queue(CVE, record(), NOW)
        self.db.queue(OTHER_CVE, record(cve_id=OTHER_CVE), NOW)
        summary = app.RunSummary()
        with patch.object(
            app, "send_notification", return_value=app.DeliveryResult(False, True)
        ) as send:
            app.deliver_pending(CONFIG, self.db, NOW, summary)
        send.assert_called_once()
        self.assertEqual(summary.pending, 2)

    def test_bad_archive_does_not_retire_earlier_404(self):
        with patch.object(app, "fetch_url", side_effect=[None] + [b"invalid zip"] * 23):
            result = app.run_pipeline(CONFIG, self.db, now=NOW)
        self.assertEqual(self.db.processed_releases(), set())
        self.assertEqual(result.errors, 23)

    def test_malformed_json_is_reported_without_repeated_downloads(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as output:
            output.writestr(f"{CVE}.json", "{")
        with patch.object(app, "fetch_url", return_value=data.getvalue()):
            result = app.run_pipeline(CONFIG, self.db, now=NOW)
        self.assertEqual(result.invalid_records, 24)
        self.assertEqual(len(self.db.processed_releases()), 24)
        self.assertEqual(result.exit_code, 1)
