"""Regression tests for httpandcli."""

import http.client
import io
import json
import logging
import unittest
import urllib.error
from dataclasses import replace
from unittest.mock import patch

import patch_sentinel as app
from tests.support import CONFIG, CVE, WEBHOOK, record


class HttpAndCliTests(unittest.TestCase):
    def test_fetch_distinguishes_missing_and_failed_requests(self):
        for status in (404, 429, 500):
            error = urllib.error.HTTPError("https://example.com", status, "error", {}, None)
            with patch.object(app.urllib.request, "urlopen", side_effect=error):
                if status == 404:
                    self.assertIsNone(app.fetch_url("https://example.com"))
                else:
                    with self.assertRaises(app.FetchError):
                        app.fetch_url("https://example.com")

    def test_truncated_response_remains_retryable(self):
        with (
            patch.object(
                app.urllib.request, "urlopen", side_effect=http.client.IncompleteRead(b"partial")
            ),
            self.assertRaises(app.FetchError),
        ):
            app.fetch_url("https://example.com")

    def test_download_size_limit(self):
        with (
            patch.object(app, "MAX_DOWNLOAD_BYTES", 4),
            patch.object(app.urllib.request, "urlopen") as request,
        ):
            request.return_value.__enter__.return_value.read.return_value = b"12345"
            with self.assertRaises(app.FetchError):
                app.fetch_url("https://example.com")
            request.return_value.__enter__.return_value.read.assert_called_once_with(5)

    def test_discord_rate_limit_stops_delivery(self):
        error = urllib.error.HTTPError(WEBHOOK, 429, "rate limited", {}, None)
        with patch.object(app.urllib.request, "urlopen", side_effect=error):
            result = app.send_notification(
                replace(CONFIG, test_mode=False, webhook_url=WEBHOOK),
                app.parse_cve(CVE, record()),
                "Linux",
            )
        self.assertFalse(result.success)
        self.assertTrue(result.stop_batch)

    def test_payload_fields_are_bounded(self):
        cve = replace(app.parse_cve(CVE, record()), description="x" * 5000)
        with patch.object(app.urllib.request, "urlopen") as request:
            result = app.send_notification(
                replace(CONFIG, test_mode=False, webhook_url=WEBHOOK), cve, "y" * 5000
            )
        self.assertTrue(result.success)
        payload = json.loads(request.call_args.args[0].data)
        self.assertTrue(all(len(item["value"]) <= 1024 for item in payload["embeds"][0]["fields"]))

    def test_redaction_includes_tracebacks(self):
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        handler.setFormatter(app.RedactingFormatter(WEBHOOK))
        log = logging.Logger("redaction-test")
        log.addHandler(handler)
        try:
            raise ValueError(WEBHOOK)
        except ValueError:
            log.exception("failure %s", WEBHOOK)
        self.assertNotIn("secret", output.getvalue())
        self.assertIn("Traceback", output.getvalue())

    def test_test_mode_uses_isolated_database(self):
        with (
            patch.object(app, "load_config", return_value=CONFIG),
            patch.object(app, "Database") as database,
            patch.object(app, "run_pipeline", return_value=app.RunSummary()),
        ):
            self.assertEqual(app.main(["--test"]), 0)
        database.assert_called_once_with(":memory:")

    def test_invalid_config_has_distinct_exit_code(self):
        with (
            patch.object(app, "load_config", side_effect=app.ConfigError("invalid")),
            patch.object(app, "logger"),
        ):
            self.assertEqual(app.main([]), 2)

    def test_programming_errors_surface_at_cli_boundary(self):
        with (
            patch.object(app, "load_config", return_value=CONFIG),
            patch.object(app, "run_pipeline", side_effect=RuntimeError("bug")),
            patch.object(app, "logger") as log,
        ):
            self.assertEqual(app.main([]), 1)
        log.exception.assert_called_once()
