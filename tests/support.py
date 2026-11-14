"""Shared deterministic CVE fixtures; no live network access."""

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta

import patch_sentinel as app

NOW = datetime(2026, 11, 13, 12, 30, tzinfo=UTC)
CONFIG = app.Config(("Linux",), test_mode=True, min_score=7)
CVE = "CVE-2026-1234"
OTHER_CVE = "CVE-2026-5678"
WEBHOOK = "https://discord.com/api/webhooks/123/secret"


def record(age=1, score=8, cve_id=CVE):
    return {
        "cveMetadata": {"cveId": cve_id, "datePublished": (NOW - timedelta(hours=age)).isoformat()},
        "containers": {
            "cna": {
                "affected": [{"product": "Linux"}],
                "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
                "metrics": [{"cvssV3_1": {"baseScore": score, "baseSeverity": "HIGH"}}],
            }
        },
    }


def archive(value, cve_id=CVE):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as output:
        output.writestr(f"{cve_id}.json", json.dumps(value))
    return data.getvalue()
