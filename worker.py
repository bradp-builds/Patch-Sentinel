# worker.py
from workers import WorkerEntrypoint
from js import fetch as js_fetch, Headers, Response
import json
import cve_engine


class CloudflareDBAdapter(cve_engine.DBAdapter):
	def __init__(self, d1_binding):
		self.db = d1_binding
		self.db.prepare(
			"CREATE TABLE IF NOT EXISTS processed_diffs (release_id TEXT PRIMARY KEY, processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
		).run()
		self.db.prepare(
			"CREATE TABLE IF NOT EXISTS sent_notifications (cve_id TEXT, local_date TEXT, notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (cve_id, local_date));"
		).run()

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


async def cf_fetch(url):
	try:
		res = await js_fetch(url)
		if res.status == 404:
			return None
		if res.status != 200:
			print(f"⚠️ GitHub release returned status {res.status}")
			return None
		buf = await res.arrayBuffer()
		return bytes(buf.to_py())
	except Exception as e:
		print(f"❌ Fetch error for {url}: {e}")
		return None


async def cf_notify(config, cve_id, product, severity, desc):
	url = config["providers"]["discord"]["webhook_url"]
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
		hdrs = Headers.new(
			{"Content-Type": "application/json", "User-Agent": "PatchSentinel/1.0"}
		)
		await js_fetch(url, method="POST", body=json.dumps(payload), headers=hdrs)
		print(f"✅ Alert distributed for {cve_id}")
	except Exception as e:
		print(f"❌ Notification runtime fail for {cve_id}: {e}")


def _build_config(env):
	provider = env.PATCH_SENTINEL_PROVIDER
	if provider != "discord":
		raise ValueError(
			f"PATCH_SENTINEL_PROVIDER must be 'discord'. Got '{provider}'. Slack support has been removed."
		)
	config = {
		"notification_provider": "discord",
		"providers": {
			"discord": {
				"webhook_url": env.DISCORD_WEBHOOK_URL
			}
		},
		"timezone": getattr(env, "TIMEZONE", "UTC"),
		"min_severity_score": float(env.MIN_SEVERITY_SCORE)
		if getattr(env, "MIN_SEVERITY_SCORE", None) is not None
		else None,
		"monitored_sources": [],
	}
	if getattr(env, "MONITORED_SOURCES", None):
		for line in str(env.MONITORED_SOURCES).splitlines():
			for part in line.split(","):
				if part.strip():
					config["monitored_sources"].append(part.strip())
	return config


class Default(WorkerEntrypoint):
	async def fetch(self, request):
		config = _build_config(self.env)
		db_adapter = CloudflareDBAdapter(self.env.DB)
		await cve_engine.run_engine(config, db_adapter, cf_fetch, cf_notify)
		return Response.new("Patch Sentinel Execution Complete")

	async def scheduled(self, controller, env, ctx):
		config = _build_config(env)
		db_adapter = CloudflareDBAdapter(env.DB)
		await cve_engine.run_engine(config, db_adapter, cf_fetch, cf_notify)
