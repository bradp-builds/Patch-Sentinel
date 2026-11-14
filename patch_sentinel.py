#!/usr/bin/env python3
"""Monitor recent CVE releases and deliver matching alerts to Discord."""

from __future__ import annotations

import argparse
import fnmatch
import http.client
import io
import json
import logging
import math
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_DB_PATH = "local_db.sqlite"
LOOKBACK = timedelta(hours=24)
RETENTION = timedelta(hours=48)
DELIVERY_TTL = timedelta(hours=24)
DELIVERY_BUDGET_SECONDS = 300
MAX_RATE_LIMIT_RETRIES = 3
HTTP_TIMEOUT_SECONDS = 30
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
USER_AGENT = "PatchSentinel/1.0"
CVE_DELTA_URL_TEMPLATE = (
    "https://github.com/CVEProject/cvelistV5/releases/download/"
    "cve_{date}_{hour}00Z/{date}_delta_CVEs_at_{hour}00Z.zip"
)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}\Z")
WEBHOOK_PATTERN = re.compile(
    r"https?://[^\s\"']*/api/webhooks/[^\s\"']+|/api/webhooks/[^\s\"']+",
    re.IGNORECASE,
)
logger = logging.getLogger("patch_sentinel")


class ConfigError(ValueError):
    """Invalid user configuration."""


class RecordError(ValueError):
    """An upstream CVE record cannot be interpreted safely."""


class FetchError(Exception):
    """A download failed and must remain eligible for a later run."""


def sanitize_log(message: object, secret: str = "") -> str:
    text = str(message)
    if secret:
        text = text.replace(secret, "[REDACTED_WEBHOOK_URL]")
    return WEBHOOK_PATTERN.sub("[REDACTED_WEBHOOK_URL]", text)


class RedactingFormatter(logging.Formatter):
    """Redact the entire formatted record, including exception tracebacks."""

    def __init__(self, secret: str = "") -> None:
        super().__init__("%(levelname)s | %(message)s")
        self.secret = secret

    def format(self, record: logging.LogRecord) -> str:
        return sanitize_log(super().format(record), self.secret)


def configure_logging(secret: str = "") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(secret))
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False


@dataclass(frozen=True)
class Config:
    monitored_sources: tuple[str, ...]
    webhook_url: str = field(default="", repr=False)
    min_score: float | None = None
    test_mode: bool = False
    timezone: str = "UTC"

    def __post_init__(self) -> None:
        if not self.monitored_sources or any(
            not isinstance(item, str) or not item.strip() for item in self.monitored_sources
        ):
            raise ConfigError("monitored_sources must contain at least one nonempty pattern")
        if self.min_score is not None and (
            isinstance(self.min_score, bool)
            or not math.isfinite(self.min_score)
            or not 0 <= self.min_score <= 10
        ):
            raise ConfigError("min_severity_score must be a finite number between 0 and 10")
        if not isinstance(self.test_mode, bool):
            raise ConfigError("test_mode must be true or false")
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
            raise ConfigError("timezone must be a valid IANA timezone name") from exc
        if self.webhook_url:
            try:
                url = urllib.parse.urlsplit(self.webhook_url)
                valid = (
                    url.scheme == "https"
                    and url.hostname in {"discord.com", "discordapp.com"}
                    and url.port in {None, 443}
                    and url.username is None
                    and url.password is None
                    and re.fullmatch(r"/api/webhooks/\d+/[^/\s]+", url.path) is not None
                    and not url.fragment
                    and not url.query
                )
            except ValueError:
                valid = False
            if not valid:
                raise ConfigError("discord_webhook_url must be an HTTPS Discord webhook URL")
        elif not self.test_mode:
            raise ConfigError("discord_webhook_url is required outside test mode")


def normalize_sources(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part.strip() for part in re.split(r"[,\n]", value) if part.strip())
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(item.strip() for item in value if item.strip())
    raise ConfigError("monitored_sources must be a list of strings or comma/newline-separated text")


def parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false", ""}:
        return value.strip().lower() == "true"
    raise ConfigError("test_mode must be true or false")


def config_from_mapping(raw: Mapping[str, Any], *, test: bool = False) -> Config:
    allowed = {
        "discord_webhook_url",
        "monitored_sources",
        "min_severity_score",
        "test_mode",
        "timezone",
    }
    unknown = raw.keys() - allowed
    if unknown:
        names = ", ".join(sorted(str(key) for key in unknown))
        raise ConfigError(f"unknown configuration keys: {names}")
    webhook = raw.get("discord_webhook_url", "")
    if not isinstance(webhook, str):
        raise ConfigError("discord_webhook_url must be a string")
    score = raw.get("min_severity_score")
    if score is not None and score != "":
        try:
            if isinstance(score, bool):
                raise ValueError
            score = float(score)
        except (TypeError, ValueError) as exc:
            raise ConfigError("min_severity_score must be a number between 0 and 10") from exc
    else:
        score = None
    tz_name = raw.get("timezone", "UTC")
    if not isinstance(tz_name, str):
        raise ConfigError("timezone must be a string")
    test_mode = parse_bool(raw.get("test_mode", False))
    return Config(
        monitored_sources=normalize_sources(raw.get("monitored_sources", [])),
        webhook_url=webhook.strip(),
        min_score=score,
        test_mode=test or test_mode,
        timezone=tz_name.strip() or "UTC",
    )


def load_config(config_path: str | None = None, *, test: bool = False) -> Config:
    """Explicit file, environment-selected file, environment mode, then config.yaml."""
    env_path = os.environ.get("PATCH_SENTINEL_CONFIG")
    if config_path is None and env_path is None and "DISCORD_WEBHOOK_URL" in os.environ:
        raw = {
            "discord_webhook_url": os.environ.get("DISCORD_WEBHOOK_URL", ""),
            "monitored_sources": os.environ.get("MONITORED_SOURCES", ""),
            "min_severity_score": os.environ.get("MIN_SEVERITY_SCORE", ""),
            "test_mode": os.environ.get("TEST_MODE", "false"),
            "timezone": os.environ.get("TIMEZONE", "UTC"),
        }
    else:
        try:
            import yaml
        except ImportError as exc:
            raise ConfigError("install PyYAML to use YAML configuration") from exc
        try:
            raw = yaml.safe_load(
                Path(config_path or env_path or "config.yaml").read_text(encoding="utf-8")
            )
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot read YAML configuration: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError("configuration must be a YAML mapping")
    return config_from_mapping(raw, test=test)


@dataclass(frozen=True)
class Cve:
    cve_id: str
    published: datetime
    products: tuple[str, ...]
    description: str
    score: float | None
    severity: str


def parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or "T" not in value:
        raise RecordError("datePublished must be an ISO timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RecordError("datePublished is invalid") from exc
    return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)


def extract_metrics(metrics: list[Any]) -> tuple[float | None, str]:
    """Prefer the newest supported CVSS version with a valid score."""
    for version in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        for metric in metrics:
            values = metric.get(version) if isinstance(metric, dict) else None
            if not isinstance(values, dict):
                continue
            raw = values.get("baseScore")
            try:
                if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
                    continue
                score = float(raw)
            except (TypeError, ValueError):
                continue
            if math.isfinite(score) and 0 <= score <= 10:
                severity = values.get("baseSeverity", "UNKNOWN")
                return score, f"{severity} ({score:g})"
    return None, "UNKNOWN"


def parse_cve(cve_id: str, raw: object) -> Cve:
    """Normalize untrusted JSON. Invalid records never edit delivery state."""
    if not isinstance(raw, dict):
        raise RecordError("record must be an object")
    metadata = raw.get("cveMetadata")
    containers = raw.get("containers")
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        raise RecordError("missing metadata or containers")
    if metadata.get("cveId") != cve_id or not CVE_ID.fullmatch(cve_id):
        raise RecordError("record ID does not match archive filename")
    cna = containers.get("cna")
    if not isinstance(cna, dict):
        raise RecordError("missing CNA container")
    affected = cna.get("affected", [])
    descriptions = cna.get("descriptions", [])
    metrics = cna.get("metrics", [])
    if not all(isinstance(value, list) for value in (affected, descriptions, metrics)):
        raise RecordError("affected, descriptions and metrics must be arrays")
    products = tuple(
        item["product"].strip()
        for item in affected
        if isinstance(item, dict)
        and isinstance(item.get("product"), str)
        and item["product"].strip()
    )
    texts = [
        item
        for item in descriptions
        if isinstance(item, dict) and isinstance(item.get("value"), str) and item["value"].strip()
    ]
    description = next((item["value"] for item in texts if item.get("lang") == "en"), None)
    if description is None:
        description = texts[0]["value"] if texts else "No description provided"
    score, severity = extract_metrics(metrics)
    return Cve(
        cve_id,
        parse_timestamp(metadata.get("datePublished")),
        products,
        description,
        score,
        severity,
    )


def matching_product(
    cve: Cve, config: Config, now: datetime, *, queued: bool = False
) -> str | None:
    """Apply publication, product and score policy without side effects."""
    if not queued and not now - LOOKBACK <= cve.published <= now:
        return None
    if config.min_score is not None and (cve.score is None or cve.score < config.min_score):
        return None
    for product in cve.products:
        if any(
            fnmatch.fnmatchcase(product.casefold(), pattern.casefold())
            for pattern in config.monitored_sources
        ):
            return product
    if not cve.products:
        for pattern in config.monitored_sources:
            text = pattern.replace("*", "").replace("?", "").strip()
            if text and text.casefold() in cve.description.casefold():
                return pattern
    return None


class Database:
    """Persist releases and pending deliveries; migrate legacy databases atomically."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH, *, now: datetime | None = None) -> None:
        self._conn = sqlite3.connect(db_path)
        try:
            self._init_db(now or datetime.now(UTC))
        except Exception:
            self._conn.close()
            raise

    def _init_db(self, now: datetime) -> None:
        if self._conn.execute("PRAGMA user_version").fetchone()[0] > 2:
            raise sqlite3.DatabaseError("database was created by a newer Patch Sentinel version")
        with self._conn:
            # Explicit BEGIN also covers DDL in the migration transaction.
            self._conn.execute("BEGIN")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_diffs (
                    release_id TEXT PRIMARY KEY,
                    processed_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_notifications (
                    cve_id TEXT PRIMARY KEY,
                    record TEXT NOT NULL
                )
                """
            )
            columns = {
                row[1] for row in self._conn.execute("PRAGMA table_info(sent_notifications)")
            }
            if "local_date" in columns:
                self._conn.execute(
                    """
                    CREATE TABLE sent_notifications_new (
                        cve_id TEXT PRIMARY KEY,
                        notified_at TEXT NOT NULL
                    )
                    """
                )
                self._conn.execute(
                    """
                    INSERT INTO sent_notifications_new (cve_id, notified_at)
                    SELECT cve_id, MAX(notified_at)
                    FROM sent_notifications
                    GROUP BY cve_id
                    """
                )
                self._conn.execute("DROP TABLE sent_notifications")
                self._conn.execute(
                    "ALTER TABLE sent_notifications_new RENAME TO sent_notifications"
                )
            else:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sent_notifications (
                        cve_id TEXT PRIMARY KEY,
                        notified_at TEXT NOT NULL
                    )
                    """
                )
            pending_columns = {
                row[1] for row in self._conn.execute("PRAGMA table_info(pending_notifications)")
            }
            if "queued_at" not in pending_columns:
                self._conn.execute(
                    "ALTER TABLE pending_notifications ADD COLUMN queued_at TEXT NOT NULL DEFAULT ''"
                )
                # Older queues have no discovery timestamp. Give existing work one delivery window.
                self._conn.execute(
                    "UPDATE pending_notifications SET queued_at = ?",
                    (now.astimezone(UTC).isoformat(),),
                )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS delivery_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    not_before TEXT NOT NULL
                )
                """
            )
            self._conn.execute("PRAGMA user_version = 2")

    def processed_releases(self) -> set[str]:
        return {row[0] for row in self._conn.execute("SELECT release_id FROM processed_diffs")}

    def mark_processed(self, release_id: str, now: datetime) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO processed_diffs (release_id, processed_at)
                VALUES (?, ?)
                """,
                (release_id, db_timestamp(now)),
            )

    def has_notified(self, cve_id: str) -> bool:
        return (
            self._conn.execute(
                "SELECT 1 FROM sent_notifications WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            is not None
        )

    def queue(self, cve_id: str, raw: dict[str, Any], now: datetime) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO pending_notifications (cve_id, record, queued_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET record = excluded.record
                """,
                (cve_id, json.dumps(raw), now.astimezone(UTC).isoformat()),
            )

    def pending(self) -> list[tuple[str, str, str]]:
        return list(
            self._conn.execute(
                """
                SELECT cve_id, record, queued_at
                FROM pending_notifications
                ORDER BY queued_at, cve_id
                """
            )
        )

    def delivery_not_before(self) -> datetime | None:
        row = self._conn.execute("SELECT not_before FROM delivery_state WHERE id = 1").fetchone()
        return datetime.fromisoformat(row[0]) if row else None

    def defer_delivery(self, until: datetime) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO delivery_state (id, not_before)
                VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE
                SET not_before = MAX(not_before, excluded.not_before)
                """,
                (until.astimezone(UTC).isoformat(),),
            )

    def remove_pending(self, cve_id: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM pending_notifications WHERE cve_id = ?", (cve_id,))

    def record_delivery(self, cve_id: str, now: datetime) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO sent_notifications (cve_id, notified_at)
                VALUES (?, ?)
                """,
                (cve_id, db_timestamp(now)),
            )
            self._conn.execute("DELETE FROM pending_notifications WHERE cve_id = ?", (cve_id,))

    def cleanup(self, now: datetime) -> None:
        with self._conn:
            cutoff = db_timestamp(now - RETENTION)
            self._conn.execute("DELETE FROM processed_diffs WHERE processed_at < ?", (cutoff,))
            self._conn.execute("DELETE FROM sent_notifications WHERE notified_at < ?", (cutoff,))

    def close(self) -> None:
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


def db_timestamp(now: datetime) -> str:
    return now.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def fetch_url(url: str) -> bytes | None:
    """Only a 404 means absent; all other failures leave the slot retryable."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            data = response.read(MAX_DOWNLOAD_BYTES + 1)
            if not isinstance(data, bytes):
                raise TypeError("HTTP response body must be bytes")
        if len(data) > MAX_DOWNLOAD_BYTES:
            raise FetchError("release exceeds download size limit")
        return data
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404:
            return None
        raise FetchError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as exc:
        raise FetchError(str(exc)) from exc


@dataclass(frozen=True)
class DeliveryResult:
    success: bool
    stop_batch: bool = False
    retry_after: float | None = None


def delay_seconds(value: object) -> float | None:
    """Ignore missing, malformed and nonfinite server timing values."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        delay = float(value)
    except (ValueError, OverflowError):
        return None
    return delay if math.isfinite(delay) and 0 <= delay <= timedelta.max.total_seconds() else None


def send_notification(config: Config, cve: Cve, product: str) -> DeliveryResult:
    if config.test_mode:
        logger.info("TEST ALERT | %s | %s | %s", cve.cve_id, product, cve.severity)
        return DeliveryResult(True)
    payload = {
        "embeds": [
            {
                "title": f"Vulnerability Detected: {cve.cve_id}",
                "color": 16711680,
                "fields": [
                    {"name": "Impacted Software", "value": product[:1024], "inline": True},
                    {"name": "Severity", "value": cve.severity[:1024], "inline": True},
                    {
                        "name": "Published",
                        "value": cve.published.astimezone(ZoneInfo(config.timezone)).isoformat(),
                    },
                    {"name": "Description", "value": cve.description[:1024]},
                ],
            }
        ]
    }
    request = urllib.request.Request(
        config.webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            delay = None
            if response.headers.get("X-RateLimit-Remaining") == "0":
                delay = delay_seconds(response.headers.get("X-RateLimit-Reset-After"))
    except urllib.error.HTTPError as exc:
        delay = None
        try:
            if exc.code == 429:
                delay = delay_seconds(exc.headers.get("Retry-After"))
                if delay is None:
                    try:
                        body = json.loads(exc.read(16 * 1024))
                        delay = (
                            delay_seconds(body.get("retry_after"))
                            if isinstance(body, dict)
                            else None
                        )
                    except (ValueError, OSError, http.client.HTTPException):
                        pass
        finally:
            exc.close()
        logger.warning("Delivery failed | %s | HTTP %s", cve.cve_id, exc.code)
        return DeliveryResult(False, exc.code in {401, 403, 404, 429} or exc.code >= 500, delay)
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as exc:
        logger.error("Delivery failed | %s | %s", cve.cve_id, exc)
        return DeliveryResult(False, True)
    logger.info("ALERT SENT | %s | %s | %s", cve.cve_id, product, cve.severity)
    return DeliveryResult(True, retry_after=delay)


@dataclass
class RunSummary:
    downloaded: int = 0
    missing: int = 0
    retired: int = 0
    invalid_records: int = 0
    sent: int = 0
    pending: int = 0
    expired: int = 0
    errors: int = 0

    @property
    def exit_code(self) -> int:
        return 1 if self.errors or self.pending or self.expired else 0


def process_zip_data(
    config: Config, data: bytes, db: Database, now: datetime, summary: RunSummary
) -> None:
    """Queue valid matches. Deterministically malformed records are logged and skipped."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if sum(entry.file_size for entry in entries) > MAX_ARCHIVE_BYTES:
            raise zipfile.BadZipFile("archive exceeds uncompressed size limit")
        for entry in sorted(entries, key=lambda item: item.filename):
            cve_id = Path(entry.filename).stem
            if not entry.filename.endswith(".json") or not CVE_ID.fullmatch(cve_id):
                continue
            try:
                if entry.file_size > MAX_RECORD_BYTES:
                    raise RecordError("record exceeds size limit")
                if entry.flag_bits & 1:
                    raise zipfile.BadZipFile("encrypted archive entry")
                raw = json.loads(archive.read(entry))
                cve = parse_cve(cve_id, raw)
            except (RecordError, ValueError, UnicodeDecodeError) as exc:
                summary.invalid_records += 1
                summary.errors += 1
                logger.warning("Invalid record | %s | %s", cve_id, exc)
                continue
            if not db.has_notified(cve_id) and matching_product(cve, config, now) is not None:
                db.queue(cve_id, raw, now)


def wait_for_cooldown(
    db: Database, current_time: Callable[[], datetime], started: float, expires: datetime
) -> bool:
    """Wait only if the cooldown fits both the delivery budget and alert lifetime."""
    while True:
        current = current_time()
        not_before = db.delivery_not_before()
        wait = max(0.0, (not_before - current).total_seconds()) if not_before else 0.0
        remaining = DELIVERY_BUDGET_SECONDS - (time.monotonic() - started)
        if wait >= (expires - current).total_seconds() or wait + HTTP_TIMEOUT_SECONDS > remaining:
            return False
        if not wait:
            return True
        logger.info("Discord cooldown | waiting %.2f seconds", wait)
        time.sleep(min(wait, 60.0))


def deliver_pending(config: Config, db: Database, now: datetime, summary: RunSummary) -> None:
    """Pace a bounded delivery batch; durable deadlines survive retries and restarts."""
    started = time.monotonic()

    def current_time() -> datetime:
        return now + timedelta(seconds=time.monotonic() - started)

    # Clean the whole queue even if a rate limit later stops delivery.
    eligible: list[tuple[Cve, str, datetime]] = []
    for cve_id, serialized, queued_at in db.pending():
        try:
            cve = parse_cve(cve_id, json.loads(serialized))
            expires = datetime.fromisoformat(queued_at) + DELIVERY_TTL
            if expires.tzinfo is None:
                raise RecordError("queue timestamp must be timezone aware")
        except (RecordError, ValueError, OverflowError) as exc:
            summary.errors += 1
            logger.error("Discarding invalid pending record | %s | %s", cve_id, exc)
            db.remove_pending(cve_id)
            continue
        if current_time() >= expires:
            summary.expired += 1
            logger.warning("Delivery expired | %s", cve_id)
            db.remove_pending(cve_id)
            continue
        product = matching_product(cve, config, current_time(), queued=True)
        if db.has_notified(cve_id) or product is None:
            db.remove_pending(cve_id)
            continue
        eligible.append((cve, product, expires))

    stop_batch = False
    for cve, product, expires in eligible:
        retries = 0
        while True:
            current = current_time()
            if current >= expires:
                summary.expired += 1
                logger.warning("Delivery expired | %s", cve.cve_id)
                db.remove_pending(cve.cve_id)
                break
            if not wait_for_cooldown(db, current_time, started, expires):
                if current_time() >= expires:
                    continue  # Let the expiry branch above record and remove the alert.
                break
            result = send_notification(config, cve, product)
            if result.retry_after is not None:
                # A small margin avoids retrying exactly on the server's reset boundary.
                try:
                    until = current_time() + timedelta(seconds=result.retry_after + 0.05)
                except OverflowError:
                    until = datetime.max.replace(tzinfo=UTC)
                db.defer_delivery(until)
            if result.success:
                db.record_delivery(cve.cve_id, current_time())
                summary.sent += 1
                break
            if result.retry_after is not None and retries < MAX_RATE_LIMIT_RETRIES:
                retries += 1
                continue
            summary.errors += 1
            stop_batch = result.stop_batch
            break
        if stop_batch:
            break
    summary.pending = len(db.pending())


def release_slots(now: datetime) -> Iterator[tuple[datetime, str]]:
    """Yield UTC hourly slots in the inclusive lookback window, oldest first."""
    if now.tzinfo is None:
        raise ValueError("release clock must be timezone aware")
    now = now.astimezone(UTC)
    cutoff = now - LOOKBACK
    slot = cutoff.replace(minute=0, second=0, microsecond=0)
    if slot < cutoff:
        slot += timedelta(hours=1)
    while slot <= now:
        yield slot, slot.strftime("%Y-%m-%d_%H00Z")
        slot += timedelta(hours=1)


def run_pipeline(config: Config, db: Database, *, now: datetime | None = None) -> RunSummary:
    started = time.monotonic()
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("pipeline clock must be timezone aware")
    now = now.astimezone(UTC)
    summary = RunSummary()
    db.cleanup(now)
    processed = db.processed_releases()
    latest = max(processed, default="")
    missing = []
    for dt, release_id in release_slots(now):
        if release_id in processed:
            continue
        url = CVE_DELTA_URL_TEMPLATE.format(date=dt.strftime("%Y-%m-%d"), hour=dt.strftime("%H"))
        try:
            data = fetch_url(url)
        except FetchError as exc:
            summary.errors += 1
            logger.error("Download failed | %s | %s", release_id, exc)
            continue
        if data is None:
            summary.missing += 1
            missing.append(release_id)
            continue
        summary.downloaded += 1
        try:
            process_zip_data(config, data, db, now, summary)
        except (zipfile.BadZipFile, EOFError, NotImplementedError, zlib.error) as exc:
            summary.errors += 1
            logger.error("Invalid archive | %s | %s", release_id, exc)
            continue
        # Only a readable archive counts as evidence that a later release exists.
        latest = max(latest, release_id)
        db.mark_processed(release_id, now)
    for release_id in missing:
        if release_id < latest:
            db.mark_processed(release_id, now)
            summary.retired += 1
    delivery_now = now + timedelta(seconds=time.monotonic() - started)
    deliver_pending(config, db, delivery_now, summary)
    logger.info(
        "Run complete | downloaded=%d missing=%d retired=%d invalid=%d sent=%d pending=%d expired=%d errors=%d",
        summary.downloaded,
        summary.missing,
        summary.retired,
        summary.invalid_records,
        summary.sent,
        summary.pending,
        summary.expired,
        summary.errors,
    )
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Patch Sentinel CVE monitor")
    parser.add_argument("--config", help="YAML configuration file")
    parser.add_argument(
        "-t", "--test", action="store_true", help="Print alerts using isolated in-memory state"
    )
    args = parser.parse_args(argv)
    configure_logging()
    try:
        config = load_config(args.config, test=args.test)
        configure_logging(config.webhook_url)
        with Database(":memory:" if config.test_mode else DEFAULT_DB_PATH) as db:
            return run_pipeline(config, db).exit_code
    except ConfigError as exc:
        logger.error("Configuration error | %s", exc)
        return 2
    except Exception:
        logger.exception("Fatal execution failure")
        return 1


if __name__ == "__main__":
    sys.exit(main())
