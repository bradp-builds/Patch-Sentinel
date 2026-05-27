# src/worker.py
from js import fetch, Headers, Response
import json
import asyncio
import cve_engine

# TODO This is how we create the d1 table
# wrangler d1 execute <DATABASE_NAME> --command "CREATE TABLE IF NOT EXISTS processed_diffs (release_id TEXT PRIMARY KEY, processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS sent_notifications (cve_id TEXT, local_date TEXT, notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (cve_id, local_date));"


class CloudflareDBAdapter(cve_engine.DBAdapter):
	def __init__(self, d1_binding):
		self.db = d1_binding

	def is_diff_processed(self, release_id: str) -> bool:
		return (
			self.db.prepare("SELECT 1 FROM processed_diffs WHERE release_id = ?")
			.bind(release_id)
			.first()
			is not None
		)

	def mark_diff_processed(self, release_id: str):
		self.db.prepare(
			"INSERT OR IGNORE INTO processed_diffs (release_id) VALUES (?)"
		).bind(release_id).run()

	def has_notified_today(self, cve_id: str, local_date: str) -> bool:
		return (
			self.db.prepare(
				"SELECT 1 FROM sent_notifications WHERE cve_id = ? AND local_date = ?"
			)
			.bind(cve_id, local_date)
			.first()
			is not None
		)

	def record_notification(self, cve_id: str, local_date: str):
		self.db.prepare(
			"INSERT OR IGNORE INTO sent_notifications (cve_id, local_date) VALUES (?, ?)"
		).bind(cve_id, local_date).run()


def cf_fetch(url):
	async def _async_fetch():
		res = await fetch(url)
		if res.status == 404:
			return None
		if res.status != 200:
			raise Exception(f"GitHub release returned status {res.status}")
		buf = await res.arrayBuffer()
		return bytes(buf.to_py())

	return asyncio.run(_async_fetch())


def cf_notify(config, cve_id, product, severity, desc):
	if config.get("test_mode", False):
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

	async def _async_send():
		hdrs = Headers.new(
			{"Content-Type": "application/json", "User-Agent": "PatchSentinel/1.0"}
		)
		await fetch(url, method="POST", body=json.dumps(payload), headers=hdrs)

	asyncio.run(_async_send())


def _build_config(env):
	provider = env.PATCH_SENTINEL_PROVIDER
	config = {
		"notification_provider": provider,
		"providers": {
			provider: {
				"webhook_url": env.DISCORD_WEBHOOK_URL
				if provider == "discord"
				else env.SLACK_WEBHOOK_URL
			}
		},
		"test_mode": str(getattr(env, "TEST_MODE", "")).lower() == "true",
		"timezone": getattr(env, "TIMEZONE", "America/Detroit"),
		"min_severity_score": float(env.MIN_SEVERITY_SCORE)
		if getattr(env, "MIN_SEVERITY_SCORE", None)
		else None,
		"monitored_sources": [],
	}
	if getattr(env, "MONITORED_SOURCES", None):
		for line in str(env.MONITORED_SOURCES).splitlines():
			for part in line.split(","):
				if part.strip():
					config["monitored_sources"].append(part.strip())
	return config


# Cloudflare Workers Cron Scheduled Hook Entry
async def scheduled(event, env, ctx):
	config = _build_config(env)
	db_adapter = CloudflareDBAdapter(env.DB)
	cve_engine.run_engine(config, db_adapter, cf_fetch, cf_notify)


# Optional Fetch Hook for manual HTTP debugging triggers
async def fetch_handler(request, env, ctx):
	config = _build_config(env)
	db_adapter = CloudflareDBAdapter(env.DB)
	cve_engine.run_engine(config, db_adapter, cf_fetch, cf_notify)
	return Response.new("Patch Sentinel Execution Complete")
