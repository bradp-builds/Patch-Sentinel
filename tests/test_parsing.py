"""Regression tests for parsing."""

import unittest
from dataclasses import replace

import patch_sentinel as app
from tests.support import CONFIG, CVE, NOW, OTHER_CVE, record


class ParsingTests(unittest.TestCase):
    def test_exact_publication_boundaries(self):
        for age, expected in (
            (24, "Linux"),
            (24.001, None),
            (0, "Linux"),
            (-0.001, None),
            (18, "Linux"),
        ):
            with self.subTest(age=age):
                self.assertEqual(
                    app.matching_product(app.parse_cve(CVE, record(age)), CONFIG, NOW), expected
                )

    def test_timestamp_offset_and_naive_utc(self):
        self.assertEqual(app.parse_timestamp("2026-11-13T07:30:00-05:00"), NOW)
        self.assertEqual(app.parse_timestamp("2026-11-13T12:30:00"), NOW)
        for value in ("2026-11-13", "", None, "invalid"):
            with self.assertRaises(app.RecordError):
                app.parse_timestamp(value)

    def test_malformed_description_does_not_hide_valid_english(self):
        raw = record()
        raw["containers"]["cna"]["descriptions"] = [
            None,
            {"value": 123},
            {"lang": "en", "value": "Valid"},
        ]
        self.assertEqual(app.parse_cve(CVE, raw).description, "Valid")

    def test_invalid_structures_raise_record_error(self):
        values = [None, [], {}, {"cveMetadata": []}, record(cve_id=OTHER_CVE)]
        for key in ("affected", "descriptions", "metrics"):
            raw = record()
            raw["containers"]["cna"][key] = None
            values.append(raw)
        for value in values:
            with self.subTest(value=value), self.assertRaises(app.RecordError):
                app.parse_cve(CVE, value)

    def test_metrics_prefer_newest_version_and_ignore_invalid_scores(self):
        metrics = [{"cvssV3_1": {"baseScore": 7}}, {"cvssV4_0": {"baseScore": 9}}]
        self.assertEqual(app.extract_metrics(metrics)[0], 9)
        for value in (None, True, "nan", "inf", -1, 11, "oops"):
            self.assertIsNone(app.extract_metrics([{"cvssV4_0": {"baseScore": value}}])[0])
        metrics = [{"cvssV4_0": {"baseScore": "bad"}, "cvssV3_1": {"baseScore": 8}}]
        self.assertEqual(app.extract_metrics(metrics)[0], 8)

    def test_versions_take_precedence_over_list_order_and_score_value(self):
        metrics = [
            {"cvssV2_0": {"baseScore": 9}},
            {"cvssV3_0": {"baseScore": 8}},
            {"cvssV3_1": {"baseScore": 7}},
            {"cvssV4_0": {"baseScore": 6}},
        ]
        for size, expected in enumerate((9, 8, 7, 6), start=1):
            self.assertEqual(app.extract_metrics(metrics[:size])[0], expected)

    def test_cisa_fallback_only_after_authority_scores_are_exhausted(self):
        raw = record()
        raw["containers"]["adp"] = [
            {
                "providerMetadata": {"shortName": "Other"},
                "metrics": [{"cvssV4_0": {"baseScore": 9}}],
            },
            {
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [{"cvssV3_1": {"baseScore": 8}}],
            },
        ]
        for value, expected in ((0, 0), (4, 4), ("invalid", 8)):
            raw["containers"]["cna"]["metrics"] = [{"cvssV2_0": {"baseScore": value}}]
            cve = app.parse_cve(CVE, raw)
            self.assertEqual(cve.score, expected)
            self.assertEqual(
                app.matching_product(cve, CONFIG, NOW), "Linux" if expected == 8 else None
            )

    def test_product_matching_and_description_fallback(self):
        cve = app.parse_cve(CVE, record())
        self.assertEqual(
            app.matching_product(cve, replace(CONFIG, monitored_sources=("lin*",)), NOW), "Linux"
        )
        self.assertIsNone(
            app.matching_product(
                replace(cve, products=("Other",), description="Linux"), CONFIG, NOW
            )
        )
        self.assertEqual(
            app.matching_product(
                replace(cve, products=(), description="A Linux issue"), CONFIG, NOW
            ),
            "Linux",
        )
        self.assertIsNone(app.matching_product(replace(cve, score=None), CONFIG, NOW))
        self.assertEqual(
            app.matching_product(replace(cve, score=None), replace(CONFIG, min_score=None), NOW),
            "Linux",
        )
