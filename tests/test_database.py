"""Regression tests for database."""

import json
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import patch_sentinel as app
from tests.support import CVE, NOW, OTHER_CVE, record


class DatabaseTests(unittest.TestCase):
    def test_legacy_migration_preserves_and_deduplicates_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sqlite")
            connection = sqlite3.connect(path)
            self.addCleanup(connection.close)
            with connection:
                connection.execute(
                    "CREATE TABLE sent_notifications (cve_id TEXT, local_date TEXT, notified_at TEXT, PRIMARY KEY(cve_id, local_date))"
                )
                connection.executemany(
                    "INSERT INTO sent_notifications VALUES (?, ?, ?)",
                    [
                        (CVE, "2026-11-12", "2026-11-12 12:00:00"),
                        (CVE, "2026-11-13", "2026-11-13 12:00:00"),
                    ],
                )
                connection.execute(
                    "CREATE TABLE pending_notifications (cve_id TEXT PRIMARY KEY, record TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO pending_notifications VALUES (?, ?)",
                    (OTHER_CVE, json.dumps(record(cve_id=OTHER_CVE))),
                )
            for _ in range(2):
                with app.Database(path) as db:
                    self.assertTrue(db.has_notified(CVE))
                    self.assertEqual(len(db.pending()), 1)
                    self.assertEqual(
                        db._conn.execute("SELECT COUNT(*) FROM sent_notifications").fetchone()[0], 1
                    )

    def test_success_and_pending_removal_rollback_together(self):
        with app.Database(":memory:") as db:
            db.queue(CVE, record(), NOW)
            db._conn.execute(
                "CREATE TRIGGER fail_delete BEFORE DELETE ON pending_notifications BEGIN SELECT RAISE(ABORT, 'failure'); END"
            )
            with self.assertRaises(sqlite3.IntegrityError):
                db.record_delivery(CVE, NOW)
            self.assertFalse(db.has_notified(CVE))
            self.assertEqual(len(db.pending()), 1)

    def test_cleanup_retains_48_hours_using_supplied_clock(self):
        with app.Database(":memory:") as db:
            timestamps = {
                "old": NOW - timedelta(hours=48, seconds=1),
                "boundary": NOW - timedelta(hours=48),
                "recent": NOW - timedelta(hours=47),
            }
            for key, timestamp in timestamps.items():
                db.mark_processed(key, timestamp)
                db.record_delivery(key, timestamp)
            db.queue(CVE, record(), NOW)

            db.cleanup(NOW)

            self.assertEqual(db.processed_releases(), {"boundary", "recent"})
            self.assertFalse(db.has_notified("old"))
            self.assertTrue(db.has_notified("boundary"))
            self.assertTrue(db.has_notified("recent"))
            self.assertEqual(len(db.pending()), 1)

            db.cleanup(NOW + timedelta(seconds=1))
            self.assertEqual(db.processed_releases(), {"recent"})
            self.assertFalse(db.has_notified("boundary"))

    def test_failed_migration_rolls_back_without_destroying_legacy_table(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sqlite")
            connection = sqlite3.connect(path)
            self.addCleanup(connection.close)
            with connection:
                connection.execute(
                    "CREATE TABLE sent_notifications (cve_id TEXT, local_date TEXT, notified_at TEXT)"
                )
                connection.execute(
                    "INSERT INTO sent_notifications VALUES (?, ?, NULL)", (CVE, "2026-11-13")
                )
            with self.assertRaises(sqlite3.IntegrityError):
                app.Database(path)
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(sent_notifications)")
            }
            self.assertIn("local_date", columns)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM sent_notifications").fetchone()[0], 1
            )

    def test_pending_delivery_survives_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "state.sqlite")
            with app.Database(path) as db:
                db.queue(CVE, record(), NOW)
            with app.Database(path) as db:
                self.assertEqual(json.loads(db.pending()[0][1]), record())
                db.record_delivery(CVE, NOW)
            with app.Database(path) as db:
                self.assertTrue(db.has_notified(CVE))
                self.assertEqual(db.pending(), [])
