#!/usr/bin/env python3
"""Patch Sentinel — Scrapes CVEProject/cvelistV5 hourly delta releases, matches products,
filters by CVSS score, and fires Discord webhook notifications.
"""

from __future__ import annotations

import fnmatch
import io
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any, Self

# Module Constants
DEFAULT_DB_PATH = "local_db.sqlite"
LOOKBACK_HOURS = 168
HTTP_TIMEOUT_SECONDS = 30
USER_AGENT = "PatchSentinel/1.0"
CVE_DELTA_URL_TEMPLATE = (
    "https://github.com/CVEProject/cvelistV5/releases/download/"
    "cve_{date}_{hour}00Z/{date}_delta_CVEs_at_{hour}00Z.zip"
)


class Database:
    """SQLite3 database manager for tracking processed releases and notifications."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._init_db()

    def _init_db(self):
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS processed_diffs ("
                "release_id TEXT PRIMARY KEY, "
                "processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS sent_notifications ("
                "cve_id TEXT, local_date TEXT, "
                "notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                "PRIMARY KEY (cve_id, local_date));"
            )

    def is_diff_processed(self, release_id: str) -> bool:
        cursor = self._conn.execute(
            "SELECT 1 FROM processed_diffs WHERE release_id = ?", (release_id,)
        )
        return cursor.fetchone() is not None

    def mark_diff_processed(self, release_id: str):
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO processed_diffs (release_id) VALUES (?)",
                (release_id,),
            )

    def has_notified_today(self, cve_id: str, local_date: str) -> bool:
        cursor = self._conn.execute(
            "SELECT 1 FROM sent_notifications WHERE cve_id = ? AND local_date = ?",
            (cve_id, local_date),
        )
        return cursor.fetchone() is not None

    def record_notification(self, cve_id: str, local_date: str):
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO sent_notifications (cve_id, local_date) VALUES (?, ?)",
                (cve_id, local_date),
            )

    def cleanup_old_records(self, days: int = 7):
        """Deletes entries older than `days` from processed_diffs and sent_notifications."""
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_date = cutoff_dt.strftime("%Y-%m-%d")
        cutoff_release_id = cutoff_dt.strftime("%Y-%m-%d_%H00Z")
        cutoff_timestamp = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

        with self._conn:
            self._conn.execute(
                "DELETE FROM processed_diffs WHERE processed_at < ? OR release_id < ?",
                (cutoff_timestamp, cutoff_release_id),
            )
            self._conn.execute(
                "DELETE FROM sent_notifications WHERE notified_at < ? OR local_date < ?",
                (cutoff_timestamp, cutoff_date),
            )

    def close(self):
        if self._conn:
            self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


def get_local_date(tz_name: str = "UTC") -> str:
    """Calculates the recipient's localized calendar day string (YYYY-MM-DD)."""
    utc_now = datetime.now(timezone.utc)
    try:
        from zoneinfo import ZoneInfo

        return utc_now.astimezone(ZoneInfo(tz_name)).strftime("%Y-%m-%d")
    except (ImportError, KeyError, ValueError):
        return utc_now.strftime("%Y-%m-%d")


def fetch_url(url: str) -> bytes | None:
    """Fetches data from URL using standard urllib. Returns bytes or None if 404/error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as res:
            return res.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        print(f"⚠️ GitHub release returned status {e.code}")
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"❌ Fetch error for {url}: {e}")
        return None


def send_notification(
    config: dict[str, Any], cve_id: str, product: str, severity: str, desc: str
) -> bool:
    """Sends Discord webhook notification or prints alert in test mode. Returns True if delivery succeeded."""
    if config.get("test_mode", False):
        print(
            f"[TEST MODE] Alerting for {cve_id} | Product: {product} | Severity: {severity}\nSummary: {desc[:100]}...\n"
        )
        return True

    url = config.get("discord_webhook_url") or config.get("providers", {}).get(
        "discord", {}
    ).get("webhook_url", "")
    if not url:
        print(f"⚠️ No webhook URL configured for {cve_id}", file=sys.stderr)
        return False

    desc_field = (desc[:1020] + "...") if len(desc) > 1024 else desc
    payload = {
        "embeds": [
            {
                "title": f"🚨 Vulnerability Detected: {cve_id}",
                "color": 16711680,
                "fields": [
                    {"name": "Impacted Software", "value": product, "inline": True},
                    {"name": "Severity", "value": severity, "inline": True},
                    {"name": "Description", "value": desc_field},
                ],
            }
        ]
    }
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS)
        print(f"✅ Alert distributed for {cve_id}")
        return True
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"❌ Notification runtime fail for {cve_id}: {e}", file=sys.stderr)
        return False


def extract_cve_metrics(metrics: list[Any]) -> tuple[float | None, str]:
    """Extracts base score float and formatted severity string from CNA metrics list."""
    base_score = None
    severity = "Unknown"
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        for version in ["cvssV4_0", "cvssV3_1", "cvssV3_0"]:
            if version in metric and isinstance(metric[version], dict):
                raw_score = metric[version].get("baseScore")
                if raw_score is not None:
                    try:
                        base_score = float(raw_score)
                    except (ValueError, TypeError):
                        base_score = None
                    base_sev = metric[version].get("baseSeverity", "Unknown")
                    severity = f"{base_sev} ({base_score if base_score is not None else 'N/A'})"
                    break
        if base_score is not None:
            break
    return base_score, severity


def match_monitored_product(
    affected_nodes: list[Any], desc_text: str, monitored_sources: list[str]
) -> tuple[bool, str, str]:
    """Evaluates affected products against glob patterns and falls back to description substring search."""
    matched = False
    matched_product = ""
    had_product = False
    original_name = "UNKNOWN"

    for node in affected_nodes:
        if not isinstance(node, dict):
            continue
        original_name = str(node.get("product", "") or "")
        if original_name:
            had_product = True
            if any(
                fnmatch.fnmatch(original_name.lower(), pat.lower())
                for pat in monitored_sources
            ):
                matched = True
                matched_product = original_name
                break

    if not matched and not had_product:
        for pattern in monitored_sources:
            clean_pattern = pattern.replace("*", "").replace("?", "").strip()
            if clean_pattern and clean_pattern.lower() in desc_text.lower():
                matched = True
                matched_product = pattern
                break

    return matched, matched_product, original_name


def process_zip_data(
    config: dict[str, Any],
    zip_bytes: bytes,
    db: Database,
    zip_date_str: str,
    encountered_cves: set[str],
):
    """Unzips, scans delta logs, filters by product patterns/CVSS score, and fires notifications."""
    monitored_sources = config.get("monitored_sources", [])

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        target_cves = set()

        for name in zf.namelist():
            if not name.endswith(".json") or name.endswith("schema.json"):
                continue
            cve_id = os.path.splitext(os.path.basename(name))[0]
            if cve_id.startswith("CVE-"):
                target_cves.add(cve_id)

        if not target_cves:
            return

        cve_path_map = {
            os.path.splitext(os.path.basename(n))[0]: n
            for n in zf.namelist()
            if n.endswith(".json")
        }
        local_date_str = get_local_date(config.get("timezone", "UTC"))

        for cve_id in sorted(target_cves):
            filepath = cve_path_map.get(cve_id)
            if not filepath:
                continue

            try:
                cve_record = json.loads(zf.read(filepath))

                if cve_id in encountered_cves:
                    continue
                encountered_cves.add(cve_id)

                cna = cve_record.get("containers", {}).get("cna", {})
                affected_nodes = cna.get("affected", [])
                descriptions = cna.get("descriptions", [])
                metrics = cna.get("metrics", [])

                desc_text = (
                    descriptions[0].get("value", "No description provided")
                    if descriptions and isinstance(descriptions[0], dict)
                    else "No description provided"
                )

                matched, matched_product, original_name = match_monitored_product(
                    affected_nodes, desc_text, monitored_sources
                )

                if matched:
                    if db.has_notified_today(cve_id, local_date_str):
                        print(
                            f"ℹ️ Skipping {cve_id} ({matched_product}): already notified today"
                        )
                        continue

                    base_score, severity = extract_cve_metrics(metrics)

                    min_score = config.get("min_severity_score")
                    min_score_float = None
                    if min_score is not None:
                        try:
                            min_score_float = float(min_score)
                        except (ValueError, TypeError):
                            min_score_float = None

                    if min_score_float is not None and (
                        base_score is None or base_score < min_score_float
                    ):
                        print(
                            f"⏭️ Skipping {cve_id} ({matched_product}): below minimum severity score (score={base_score}, min={min_score_float})"
                        )
                        continue

                    print(f"🔔 Notifying about {cve_id} ({matched_product})")
                    success = send_notification(
                        config, cve_id, matched_product, severity, desc_text
                    )
                    if success:
                        db.record_notification(cve_id, local_date_str)
                else:
                    print(
                        f"⏭️ Skipping {cve_id} ({original_name}): doesn't match any monitored products"
                    )

            except (
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
                zipfile.BadZipFile,
                UnicodeDecodeError,
            ) as e:
                print(f"⚠️ Parsing error on {cve_id}: {e}")
                continue
            except Exception as e:  # noqa: BLE001
                print(f"⚠️ Unexpected error on {cve_id}: {e}")
                continue


def run_pipeline(config: dict[str, Any], db: Database):
    """Evaluates the 7-day lookback horizon and processes all missing hours in order."""
    db.cleanup_old_records(days=7)
    current_utc = datetime.now(timezone.utc)

    base_dt = current_utc.replace(minute=0, second=0, microsecond=0)

    lookback_releases = []
    for i in range(LOOKBACK_HOURS, -1, -1):
        dt = base_dt - timedelta(hours=i)
        release_id = dt.strftime("%Y-%m-%d_%H00Z")
        lookback_releases.append((dt, release_id))

    unprocessed = [
        (dt, rid) for dt, rid in lookback_releases if not db.is_diff_processed(rid)
    ]

    if not unprocessed:
        print("🏁 Processing pipeline is complete and up to date.")
        return

    encountered_cves: set[str] = set()
    failed_404: list[tuple[datetime, str]] = []
    last_success_time: datetime | None = None

    for dt, release_id in unprocessed:
        date_str = dt.strftime("%Y-%m-%d")
        hour_str = dt.strftime("%H")

        url = CVE_DELTA_URL_TEMPLATE.format(date=date_str, hour=hour_str)
        zip_bytes = fetch_url(url)

        if zip_bytes is None:
            failed_404.append((dt, release_id))
            continue

        print(f"📦 Downloaded delta: {release_id}")
        process_zip_data(config, zip_bytes, db, date_str, encountered_cves)
        db.mark_diff_processed(release_id)
        last_success_time = dt

    # Mark 404s that occurred before a successful hour as permanently skipped
    for dt, release_id in failed_404:
        if last_success_time is not None and dt < last_success_time:
            print(
                f"⏭️ Skipping {release_id}: no delta available (404) and later hours have been published"
            )
            db.mark_diff_processed(release_id)


def _normalize_sources(sources_input: Any) -> list[str]:
    if isinstance(sources_input, str):
        sources_list = []
        for line in sources_input.splitlines():
            for part in line.split(","):
                if part.strip():
                    sources_list.append(part.strip())
        return sources_list
    elif isinstance(sources_input, list):
        return [str(s).strip() for s in sources_input if str(s).strip()]
    return []


def _load_config_from_env() -> dict[str, Any]:
    min_sev = os.environ.get("MIN_SEVERITY_SCORE", "").strip()
    try:
        min_score = float(min_sev) if min_sev else None
    except ValueError:
        min_score = None

    config = {
        "discord_webhook_url": os.environ.get("DISCORD_WEBHOOK_URL", ""),
        "test_mode": os.environ.get("TEST_MODE", "").lower() == "true",
        "timezone": os.environ.get("TIMEZONE", "UTC"),
        "min_severity_score": min_score,
        "monitored_sources": _normalize_sources(
            os.environ.get("MONITORED_SOURCES", "")
        ),
    }
    return config


def load_config(config_path: str | None = None) -> dict[str, Any]:
    if config_path:
        target_path = config_path
    elif "PATCH_SENTINEL_CONFIG" in os.environ:
        target_path = os.environ["PATCH_SENTINEL_CONFIG"]
    elif "DISCORD_WEBHOOK_URL" in os.environ:
        return _load_config_from_env()
    else:
        target_path = "config.yaml"

    try:
        import yaml
    except ImportError as e:
        sys.exit(
            f"❌ Failed loading config: PyYAML is required when using YAML config ({e})"
        )

    try:
        with open(target_path, "r") as f:
            cfg = yaml.safe_load(f) or {}
        if "timezone" not in cfg:
            cfg["timezone"] = "UTC"
        if "discord_webhook_url" not in cfg and "providers" in cfg:
            cfg["discord_webhook_url"] = (
                cfg.get("providers", {}).get("discord", {}).get("webhook_url", "")
            )
        cfg["monitored_sources"] = _normalize_sources(cfg.get("monitored_sources", []))
        if cfg.get("min_severity_score") is not None:
            try:
                cfg["min_severity_score"] = float(cfg["min_severity_score"])
            except (ValueError, TypeError):
                cfg["min_severity_score"] = None
        return cfg
    except (OSError, ValueError, yaml.YAMLError) as e:
        sys.exit(f"❌ Failed loading config path '{target_path}': {e}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Patch Sentinel CVE monitor")
    parser.add_argument(
        "--config", help="Explicit configuration yaml layout override file."
    )
    parser.add_argument(
        "-t",
        "--test",
        action="store_true",
        help="Enable test mode (print alerts instead of sending webhooks)",
    )
    args = parser.parse_args()
    config = load_config(args.config)
    config["test_mode"] = args.test or config.get("test_mode", False)

    with Database() as db:
        try:
            run_pipeline(config, db)
        except Exception as e:  # noqa: BLE001
            sys.exit(f"❌ Fatal execution failure in Patch Sentinel: {e}")


if __name__ == "__main__":
    main()
