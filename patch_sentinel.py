#!/usr/bin/env python3
import os
import sys
import json
import sqlite3
import urllib.request
import urllib.error

import cve_engine


def _load_config_from_env():
	provider = os.environ["PATCH_SENTINEL_PROVIDER"]
	config = {
		"notification_provider": provider,
		"providers": {
			provider: {
				"webhook_url": os.environ.get(f"{provider.upper()}_WEBHOOK_URL", "")
			}
		},
		"timezone": os.environ.get("TIMEZONE", "America/Detroit"),
		"min_severity_score": float(os.environ["MIN_SEVERITY_SCORE"])
		if "MIN_SEVERITY_SCORE" in os.environ
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
		return _load_config_from_env()
	config_path = (
		config_path or os.environ.get("PATCH_SENTINEL_CONFIG") or "config.yaml"
	)
	try:
		import yaml

		with open(config_path, "r") as f:
			cfg = yaml.safe_load(f)
		if "timezone" not in cfg:
			cfg["timezone"] = "America/Detroit"
		return cfg
	except Exception as e:
		sys.exit(f"❌ Failed loading config path '{config_path}': {e}")


class LocalDBAdapter(cve_engine.DBAdapter):
	def __init__(self, db_path="patch_sentinel.sqlite"):
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


def local_fetch(url):
	try:
		req = urllib.request.Request(url, headers={"User-Agent": "PatchSentinel/1.0"})
		with urllib.request.urlopen(req, timeout=30) as res:
			return res.read()
	except urllib.error.HTTPError as e:
		if e.code == 404:
			return None
		sys.exit(f"❌ Target HTTP Error: {e}")
	except Exception as e:
		sys.exit(f"❌ Critical Core Connection Interruption: {e}")


def local_notify(config, cve_id, product, severity, desc):
	if config.get("test_mode", False):
		print(
			f"[TEST MODE] Alerting for {cve_id} | Product: {product} | Match Level: {severity}\nSummary: {desc[:100]}...\n"
		)
		return
	provider = config["notification_provider"]
	url = config["providers"][provider]["webhook_url"]
	payload = (
		{
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
		if provider == "discord"
		else {
			"blocks": [
				{
					"type": "header",
					"text": {
						"type": "plain_text",
						"text": f"🚨 Vulnerability: {cve_id}",
					},
				},
				{
					"type": "section",
					"fields": [
						{"type": "mrkdwn", "text": f"*Software:* {product}"},
						{"type": "mrkdwn", "text": f"*Severity:* {severity}"},
					],
				},
				{
					"type": "section",
					"text": {"type": "mrkdwn", "text": f"*Description:* {desc}"},
				},
			]
		}
	)
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


def main():
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument(
		"--config", help="Explicit configuration yaml layout override file."
	)
	parser.add_argument(
		"-t", "--test", action="store_true", help="Enable test mode (print alerts instead of sending webhooks)"
	)
	args = parser.parse_args()
	config = load_config(args.config)
	config["test_mode"] = args.test
	cve_engine.run_engine(
		config, LocalDBAdapter(), local_fetch, local_notify
	)


if __name__ == "__main__":
	main()
