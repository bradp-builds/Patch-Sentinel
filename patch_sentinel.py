#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import zipfile
import io
import fnmatch
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta


class Database:
	"""SQLite3 database manager for tracking processed releases and notifications."""

	def __init__(self, db_path="local_db.sqlite"):
		self.db_path = db_path
		with sqlite3.connect(self.db_path) as conn:
			conn.execute(
				"CREATE TABLE IF NOT EXISTS processed_diffs (release_id TEXT PRIMARY KEY, processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
			)
			conn.execute(
				"CREATE TABLE IF NOT EXISTS sent_notifications (cve_id TEXT, local_date TEXT, notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (cve_id, local_date));"
			)
			conn.commit()

	def is_diff_processed(self, release_id: str) -> bool:
		with sqlite3.connect(self.db_path) as conn:
			return (
				conn.execute(
					"SELECT 1 FROM processed_diffs WHERE release_id = ?", (release_id,)
				).fetchone()
				is not None
			)

	def mark_diff_processed(self, release_id: str):
		with sqlite3.connect(self.db_path) as conn:
			conn.execute(
				"INSERT OR IGNORE INTO processed_diffs (release_id) VALUES (?)",
				(release_id,),
			)

	def has_notified_today(self, cve_id: str, local_date: str) -> bool:
		with sqlite3.connect(self.db_path) as conn:
			return (
				conn.execute(
					"SELECT 1 FROM sent_notifications WHERE cve_id = ? AND local_date = ?",
					(cve_id, local_date),
				).fetchone()
				is not None
			)

	def record_notification(self, cve_id: str, local_date: str):
		with sqlite3.connect(self.db_path) as conn:
			conn.execute(
				"INSERT OR IGNORE INTO sent_notifications (cve_id, local_date) VALUES (?, ?)",
				(cve_id, local_date),
			)


def get_local_date(tz_name="UTC"):
	"""Calculates the recipient's localized calendar day string (YYYY-MM-DD)."""
	utc_now = datetime.now(timezone.utc)
	try:
		from zoneinfo import ZoneInfo

		return utc_now.astimezone(ZoneInfo(tz_name)).strftime("%Y-%m-%d")
	except Exception:
		# Resilient fallback for edge environments lacking standard tzdata packages
		offset_hours = -4  # Default to Eastern Daylight Time (EDT)
		if "detroit" in tz_name.lower() or "eastern" in tz_name.lower():
			offset_hours = -4
		elif "central" in tz_name.lower():
			offset_hours = -5
		elif "mountain" in tz_name.lower():
			offset_hours = -6
		elif "pacific" in tz_name.lower():
			offset_hours = -7
		elif "utc" in tz_name.lower():
			offset_hours = 0
		return (utc_now + timedelta(hours=offset_hours)).strftime("%Y-%m-%d")


def fetch_url(url: str) -> bytes | None:
	"""Fetches data from URL using standard urllib. Returns bytes or None if 404/error."""
	try:
		req = urllib.request.Request(url, headers={"User-Agent": "PatchSentinel/1.0"})
		with urllib.request.urlopen(req, timeout=30) as res:
			return res.read()
	except urllib.error.HTTPError as e:
		if e.code == 404:
			return None
		print(f"⚠️ GitHub release returned status {e.code}")
		return None
	except Exception as e:
		print(f"❌ Fetch error for {url}: {e}")
		return None


def send_notification(config: dict, cve_id: str, product: str, severity: str, desc: str):
	"""Sends Discord webhook notification or prints alert in test mode."""
	if config.get("test_mode", False):
		print(
			f"[TEST MODE] Alerting for {cve_id} | Product: {product} | Severity: {severity}\nSummary: {desc[:100]}...\n"
		)
		return

	url = config.get("providers", {}).get("discord", {}).get("webhook_url", "")
	if not url:
		print(f"⚠️ No webhook URL configured for {cve_id}", file=sys.stderr)
		return

	payload = {
		"embeds": [
			{
				"title": f"🚨 Vulnerability Detected: {cve_id}",
				"color": 16711680,
				"fields": [
					{"name": "Impacted Software", "value": product, "inline": True},
					{"name": "Severity", "value": severity, "inline": True},
					{"name": "Description", "value": desc},
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
				"User-Agent": "PatchSentinel/1.0",
			},
		)
		urllib.request.urlopen(req, timeout=30)
		print(f"✅ Alert distributed for {cve_id}")
	except Exception as e:
		print(f"❌ Notification runtime fail for {cve_id}: {e}", file=sys.stderr)


def process_zip_data(config: dict, zip_bytes: bytes, db: Database, zip_date_str: str, encountered_cves: set):
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
				date_published = cve_record.get("cveMetadata", {}).get("datePublished")
				if not date_published or date_published[:10] != zip_date_str:
					continue

				if cve_id in encountered_cves:
					continue
				encountered_cves.add(cve_id)

				cna = cve_record.get("containers", {}).get("cna", {})
				affected_nodes = cna.get("affected", [])
				descriptions = cna.get("descriptions", [])
				metrics = cna.get("metrics", [])

				desc_text = (
					descriptions[0].get("value", "No description provided")
					if descriptions
					else "No description provided"
				)

				matched = False
				matched_product = ""
				had_product = False
				original_name = "UNKNOWN"
				for node in affected_nodes:
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
					# Fallback uses substring search (not glob) against description text
					for pattern in monitored_sources:
						if pattern.lower() in desc_text.lower():
							matched = True
							matched_product = pattern
							break

				if matched:
					if db.has_notified_today(cve_id, local_date_str):
						print(
							f"ℹ️ Skipping {cve_id} ({matched_product}): already notified today"
						)
						continue

					base_score = None
					severity = "Unknown"
					for metric in metrics:
						for version in ["cvssV4_0", "cvssV3_1", "cvssV3_0"]:
							if version in metric:
								base_score = metric[version].get("baseScore")
								severity = f"{metric[version].get('baseSeverity', 'Unknown')} ({base_score or 'N/A'})"
								break
						if base_score is not None:
							break

					min_score = config.get("min_severity_score")
					if min_score is not None and (base_score is None or base_score < min_score):
						print(
							f"⏭️ Skipping {cve_id} ({matched_product}): below minimum severity score (score={base_score}, min={min_score})"
						)
						continue

					print(f"🔔 Notifying about {cve_id} ({matched_product})")
					send_notification(
						config, cve_id, matched_product, severity, desc_text
					)
					db.record_notification(cve_id, local_date_str)
				else:
					print(f"⏭️ Skipping {cve_id} ({original_name}): doesn't match any monitored products")

			except Exception as e:
				print(f"⚠️ Parsing error on {cve_id}: {e}")
				continue


def run_pipeline(config: dict, db: Database):
	"""Evaluates the 7-day lookback horizon and processes all missing hours in order."""
	current_utc = datetime.now(timezone.utc)
	base_dt = current_utc.replace(minute=0, second=0, microsecond=0)

	lookback_releases = []
	for i in range(168, -1, -1):
		dt = base_dt - timedelta(hours=i)
		release_id = dt.strftime("%Y-%m-%d_%H00Z")
		lookback_releases.append((dt, release_id))

	unprocessed = [
		(dt, rid)
		for dt, rid in lookback_releases
		if not db.is_diff_processed(rid)
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

		url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{date_str}_{hour_str}00Z/{date_str}_delta_CVEs_at_{hour_str}00Z.zip"
		zip_bytes = fetch_url(url)

		if zip_bytes is None:
			failed_404.append((dt, release_id))
			continue

		print(f"📦 Downloaded delta: {release_id}")
		process_zip_data(config, zip_bytes, db, date_str, encountered_cves)
		db.mark_diff_processed(release_id)
		last_success_time = dt

	# Mark 404s that occurred before a successful hour as permanently skipped
	# since the delta for that hour will never be published
	for dt, release_id in failed_404:
		if last_success_time is not None and dt < last_success_time:
			print(f"⏭️ Skipping {release_id}: no delta available (404) and later hours have been published")
			db.mark_diff_processed(release_id)


def _load_config_from_env():
	config = {
		"notification_provider": "discord",
		"providers": {
			"discord": {
				"webhook_url": os.environ.get("DISCORD_WEBHOOK_URL", "")
			}
		},
		"test_mode": os.environ.get("TEST_MODE", "").lower() == "true",
		"timezone": os.environ.get("TIMEZONE", "UTC"),
		"min_severity_score": float(os.environ["MIN_SEVERITY_SCORE"])
		if "MIN_SEVERITY_SCORE" in os.environ and os.environ["MIN_SEVERITY_SCORE"].strip()
		else None,
		"monitored_sources": [],
	}
	sources = os.environ.get("MONITORED_SOURCES", "")
	for line in sources.splitlines():
		for part in line.split(","):
			if part.strip():
				config["monitored_sources"].append(part.strip())
	return config


def load_config(config_path=None):
	if "PATCH_SENTINEL_PROVIDER" in os.environ:
		provider = os.environ["PATCH_SENTINEL_PROVIDER"]
		if provider != "discord":
			sys.exit(
				f"❌ PATCH_SENTINEL_PROVIDER must be 'discord'. Got '{provider}'. Slack support has been removed."
			)
		return _load_config_from_env()
	config_path = (
		config_path or os.environ.get("PATCH_SENTINEL_CONFIG") or "config.yaml"
	)
	try:
		import yaml

		with open(config_path, "r") as f:
			cfg = yaml.safe_load(f)
		if "timezone" not in cfg:
			cfg["timezone"] = "UTC"
		return cfg
	except Exception as e:
		sys.exit(f"❌ Failed loading config path '{config_path}': {e}")


def main():
	import argparse

	parser = argparse.ArgumentParser(description="Patch Sentinel CVE monitor")
	parser.add_argument(
		"--config", help="Explicit configuration yaml layout override file."
	)
	parser.add_argument(
		"-t", "--test", action="store_true", help="Enable test mode (print alerts instead of sending webhooks)"
	)
	args = parser.parse_args()
	config = load_config(args.config)
	config["test_mode"] = args.test or config.get("test_mode", False)
	db = Database()
	run_pipeline(config, db)


if __name__ == "__main__":
	main()
