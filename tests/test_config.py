"""Regression tests for config."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import patch_sentinel as app
from tests.support import WEBHOOK


class ConfigTests(unittest.TestCase):
    def config(self, **kwargs):
        return app.config_from_mapping(
            {"monitored_sources": ["Linux"], "test_mode": True, **kwargs}
        )

    def test_normalizes_sources_and_quoted_booleans(self):
        config = self.config(
            monitored_sources=" Linux, nginx*\nOpenSSL ",
            test_mode="false",
            discord_webhook_url=WEBHOOK,
        )
        self.assertEqual(config.monitored_sources, ("Linux", "nginx*", "OpenSSL"))
        self.assertFalse(config.test_mode)

    def test_unknown_keys_are_reported_without_echoing_values(self):
        with self.assertRaises(app.ConfigError) as error:
            self.config(min_severity_scor="private-value", extra_setting=True)
        self.assertEqual(
            str(error.exception), "unknown configuration keys: extra_setting, min_severity_scor"
        )
        self.assertNotIn("private-value", str(error.exception))

    def test_yaml_rejects_unknown_and_nonstring_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            for setting in ("min_severity_scor: 7", "123: ignored"):
                path.write_text("monitored_sources: [Linux]\ntest_mode: true\n" + setting)
                with (
                    self.subTest(setting=setting),
                    self.assertRaisesRegex(app.ConfigError, "unknown configuration keys"),
                ):
                    app.load_config(str(path))

    def test_rejects_invalid_scores(self):
        for score in ("oops", "nan", "inf", -1, 11, True, [], {}):
            with self.subTest(score=score), self.assertRaises(app.ConfigError):
                self.config(min_severity_score=score)

    def test_rejects_invalid_configuration(self):
        for kwargs in (
            {"monitored_sources": []},
            {"monitored_sources": [1]},
            {"test_mode": "yes"},
            {"timezone": "No/Such_Zone"},
            {"timezone": []},
            {"discord_webhook_url": "http://discord.com/api/webhooks/123/token"},
            {"discord_webhook_url": "https://example.com/api/webhooks/123/token"},
            {"discord_webhook_url": "https://discord.com/api/webhooks/123/token?wait=true"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(app.ConfigError):
                self.config(**kwargs)

    def test_webhook_required_only_in_production(self):
        with self.assertRaises(app.ConfigError):
            self.config(test_mode=False)
        self.assertTrue(self.config().test_mode)

    def test_webhook_is_excluded_from_config_repr(self):
        config = self.config(discord_webhook_url=WEBHOOK)
        self.assertEqual(config.webhook_url, WEBHOOK)
        self.assertNotIn("secret", repr(config))

    def test_environment_uses_same_validation_and_empty_timezone_defaults(self):
        with patch.dict(
            "os.environ",
            {"DISCORD_WEBHOOK_URL": WEBHOOK, "MONITORED_SOURCES": "Linux", "TIMEZONE": ""},
            clear=True,
        ):
            self.assertEqual(app.load_config().timezone, "UTC")

    def test_explicit_file_overrides_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("monitored_sources: [Linux]\ntest_mode: true\n")
            with patch.dict("os.environ", {"DISCORD_WEBHOOK_URL": "invalid"}, clear=True):
                self.assertTrue(app.load_config(str(path)).test_mode)

    def test_yaml_must_be_a_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            for text in ("- item\n", "false", "", "key: ["):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(app.ConfigError):
                    app.load_config(str(path))

    def test_cli_test_override_allows_missing_webhook(self):
        with patch.dict(
            "os.environ", {"DISCORD_WEBHOOK_URL": "", "MONITORED_SOURCES": "Linux"}, clear=True
        ):
            self.assertTrue(app.load_config(test=True).test_mode)
