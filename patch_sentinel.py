#!/usr/bin/env python3
import os
import sys
import json
import time
import yaml
import urllib.request
import urllib.error
import zipfile
import io
import fnmatch
from datetime import datetime, timezone

# --- Configuration & Setup ---

def _load_config_from_env():
	provider = os.environ["PATCH_SENTINEL_PROVIDER"]
	if provider not in ["discord", "slack"]:
		sys.exit("❌ Configuration Error: PATCH_SENTINEL_PROVIDER must be exactly 'discord' or 'slack'.")

	config = {
		"notification_provider": provider,
		"providers": {},
		"test_mode": os.environ.get("TEST_MODE", "").lower() == "true",
		"monitored_sources": [],
	}

	if provider == "discord":
		webhook = os.environ.get("DISCORD_WEBHOOK_URL", "")
		if not webhook:
			sys.exit("❌ Configuration Error: DISCORD_WEBHOOK_URL is required when PATCH_SENTINEL_PROVIDER is 'discord'.")
		config["providers"]["discord"] = {"webhook_url": webhook}
	elif provider == "slack":
		webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
		if not webhook:
			sys.exit("❌ Configuration Error: SLACK_WEBHOOK_URL is required when PATCH_SENTINEL_PROVIDER is 'slack'.")
		config["providers"]["slack"] = {"webhook_url": webhook}

	min_score_raw = os.environ.get("MIN_SEVERITY_SCORE")
	if min_score_raw is not None:
		try:
			min_score = float(min_score_raw)
		except ValueError:
			sys.exit("❌ Configuration Error: MIN_SEVERITY_SCORE must be a number (e.g., 8.0).")
		if min_score < 0 or min_score > 10:
			sys.exit("❌ Configuration Error: MIN_SEVERITY_SCORE must be between 0 and 10.")
		config["min_severity_score"] = min_score

	sources_raw = os.environ.get("MONITORED_SOURCES", "")
	for line in sources_raw.splitlines():
		for part in line.split(","):
			part = part.strip()
			if part:
				config["monitored_sources"].append(part)

	return config

def load_config(config_path=None):
	if "PATCH_SENTINEL_PROVIDER" in os.environ:
		return _load_config_from_env()

	if config_path is None:
		config_path = os.environ.get("PATCH_SENTINEL_CONFIG") or "config.yaml"
	try:
		with open(config_path, "r") as f:
			config = yaml.safe_load(f)
	except Exception as e:
		sys.exit(f"❌ Failed to load config from '{config_path}': {e}. Either provide a config file or set PATCH_SENTINEL_PROVIDER and other env vars for GitHub Actions mode.")

	provider = config.get("notification_provider")
	if provider not in ["discord", "slack"]:
		sys.exit("❌ Configuration Error: 'notification_provider' must be exactly 'discord' or 'slack'.")

	if provider not in config.get("providers", {}):
		sys.exit(f"❌ Configuration Error: Provider '{provider}' is not configured in the 'providers' section.")

	min_score = config.get("min_severity_score")
	if min_score is not None:
		if not isinstance(min_score, (int, float)):
			sys.exit("❌ Configuration Error: 'min_severity_score' must be a number (e.g., 8.0).")
		if min_score < 0 or min_score > 10:
			sys.exit("❌ Configuration Error: 'min_severity_score' must be between 0 and 10.")

	return config

# --- Network Handlers ---

def fetch_cve_archive(target_date):
	cache_dir = ".cache"
	os.makedirs(cache_dir, exist_ok=True)
	
	filename = f"{target_date}_all_CVEs_at_midnight.zip.zip"
	cache_path = os.path.join(cache_dir, filename)
	
	# Return local cache if we already downloaded it
	if os.path.exists(cache_path):
		print(f"📦 Loading cached archive from disk: {cache_path}")
		return cache_path

	# Remove any stale .zip files in the cache directory before fresh download
	for entry in os.listdir(cache_dir):
		if entry.endswith(".zip"):
			try:
				os.remove(os.path.join(cache_dir, entry))
			except OSError:
				pass

	url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{target_date}_0100Z/{filename}"
	print(f"🌐 Downloading target archive: {url}")

	max_retries = 3
	for attempt in range(max_retries):
		try:
			req = urllib.request.Request(url, headers={'User-Agent': 'PatchSentinel/1.0'})
			with urllib.request.urlopen(req, timeout=30) as response, open(cache_path, 'wb') as out_file:
				out_file.write(response.read())
			return cache_path
		except urllib.error.HTTPError as e:
			if e.code == 404:
				return None
			if e.code >= 500 and attempt < max_retries - 1:
				wait = 2 ** attempt
				print(f"⚠️ Server error {e.code}, retrying in {wait}s...")
				time.sleep(wait)
				continue
			sys.exit(f"❌ Network error downloading archive: {e}")
		except (urllib.error.URLError, OSError, TimeoutError) as e:
			if attempt < max_retries - 1:
				wait = 2 ** attempt
				print(f"⚠️ Transient error: {e}, retrying in {wait}s...")
				time.sleep(wait)
				continue
			sys.exit(f"❌ Network error downloading archive: {e}")

# --- Webhook Formatters ---

def send_notification(config, cve_id, product, severity, desc):
	if config.get("test_mode", False):
		print(f"[TEST MODE] Would send alert for: {cve_id}")
		print(f"Product: {product} | Severity: {severity}")
		print(f"Desc: {desc[:100]}...")
		print()
		return

	provider = config.get("notification_provider")
	webhook_url = config["providers"][provider]["webhook_url"]

	if not webhook_url.startswith("https://"):
		print(f"❌ Invalid webhook URL for {provider}: must use HTTPS")
		return

	payload = {}
	if provider == "discord":
		payload = {
			"embeds": [{
				"title": f"🚨 Vulnerability Detected: {cve_id}",
				"color": 16711680, # Red
				"fields": [
					{"name": "Impacted Software", "value": product, "inline": True},
					{"name": "Severity", "value": severity, "inline": True},
					{"name": "Description", "value": desc}
				]
			}]
		}
	elif provider == "slack":
		payload = {
			"blocks": [
				{
					"type": "header",
					"text": {"type": "plain_text", "text": f"🚨 Vulnerability Detected: {cve_id}"}
				},
				{
					"type": "section",
					"fields": [
						{"type": "mrkdwn", "text": f"*Software:* {product}"},
						{"type": "mrkdwn", "text": f"*Severity:* {severity}"}
					]
				},
				{
					"type": "section",
					"text": {"type": "mrkdwn", "text": f"*Description:* {desc}"}
				}
			]
		}

	try:
		req = urllib.request.Request(webhook_url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json', 'User-Agent': 'PatchSentinel/1.0'})
		urllib.request.urlopen(req, timeout=30)
		print(f"✅ Notification sent for {cve_id} via {provider.capitalize()}")
		print()
	except Exception:
		print(f"❌ Failed to send {provider} notification for {cve_id}: HTTP error", file=sys.stderr)
		print()

# --- Core Extraction & Parsing Logic ---

def process_archive(config, archive_path):
	monitored_sources = config.get("monitored_sources", [])
	
	# 1. Unzip the outer .zip.zip
	with zipfile.ZipFile(archive_path, 'r') as outer_zip:
		inner_zips = [name for name in outer_zip.namelist() if name.endswith('.zip')]
		if not inner_zips:
			sys.exit("❌ Archive structure error: No inner .zip found inside the outer archive.")
		inner_zip_name = inner_zips[0]
		inner_zip_data = io.BytesIO(outer_zip.read(inner_zip_name))
		
		# 2. Unzip the inner .zip in memory
		with zipfile.ZipFile(inner_zip_data, 'r') as inner_zip:
			
			# 3. Locate delta.json
			delta_paths = [name for name in inner_zip.namelist() if name.endswith('delta.json')]
			if not delta_paths:
				sys.exit("❌ Could not find delta.json inside the archive structure.")
			
			delta_data = json.loads(inner_zip.read(delta_paths[0]))
			
			# Extract CVE IDs from the 'new' and 'updated' nodes
			target_cves = set()
			for category in ["new", "updated"]:
				for item in delta_data.get(category, []):
					cve_id = item.get("cveId") if isinstance(item, dict) else item
					if cve_id:
						target_cves.add(cve_id)
			
			print(f"🔍 Found {len(target_cves)} changed CVEs today. Scanning for stack matches...")
			print()

			# Map only the changed CVE files for fast O(1) lookups
			cve_path_map = {}
			for name in inner_zip.namelist():
				if not name.endswith('.json'):
					continue
				cve_id = os.path.splitext(os.path.basename(name))[0]
				if cve_id in target_cves:
					cve_path_map[cve_id] = name

			# 4. Parse only the changed files
			for cve_id in target_cves:
				filepath = cve_path_map.get(cve_id)
				if not filepath:
					continue
				
				cve_record = json.loads(inner_zip.read(filepath))
				
				# Dig into the CVE JSON 5 schema to find affected products
				try:
					affected_nodes = cve_record.get("containers", {}).get("cna", {}).get("affected", [])
					descriptions = cve_record.get("containers", {}).get("cna", {}).get("descriptions", [])
					metrics = cve_record.get("containers", {}).get("cna", {}).get("metrics", [])
					
					desc_text = descriptions[0].get("value", "No description provided") if descriptions else "No description provided"
					
					# Extract severity (look for CVSS v4.0, v3.1, or v3.0 score)
					base_score = None
					severity = "Unknown"
					for metric in metrics:
						if "cvssV4_0" in metric:
							base_score = metric['cvssV4_0'].get('baseScore')
							severity = f"{metric['cvssV4_0'].get('baseSeverity', 'Unknown')} ({base_score or 'N/A'})"
							break
						if "cvssV3_1" in metric:
							base_score = metric['cvssV3_1'].get('baseScore')
							severity = f"{metric['cvssV3_1'].get('baseSeverity', 'Unknown')} ({base_score or 'N/A'})"
							break
						if "cvssV3_0" in metric:
							base_score = metric['cvssV3_0'].get('baseScore')
							severity = f"{metric['cvssV3_0'].get('baseSeverity', 'Unknown')} ({base_score or 'N/A'})"
							break

					# Skip this CVE if its score is below the configured threshold
					# Unknown/missing scores always pass through
					min_score = config.get("min_severity_score")
					if min_score is not None and base_score is not None and base_score < min_score:
						continue

					for node in affected_nodes:
						original_name = str(node.get("product", "") or "")
						product_name = original_name.lower()

						for pattern in monitored_sources:
							if product_name:
								if fnmatch.fnmatch(product_name, pattern.lower()):
									send_notification(config, cve_id, original_name, severity, desc_text)
									break
							elif pattern.lower() in desc_text.lower():
								send_notification(config, cve_id, pattern, severity, desc_text)
								break
				except Exception as e:
					print(f"⚠️ Error parsing layout for {cve_id}: {e}")
					continue

def main():
	import argparse
	parser = argparse.ArgumentParser(description="Patch Sentinel — CVE monitoring tool")
	parser.add_argument("--config", help="Config file path. Ignored when PATCH_SENTINEL_PROVIDER env var is set. (default: config.yaml or $PATCH_SENTINEL_CONFIG)")
	args = parser.parse_args()
	config = load_config(args.config)
	
	today = (datetime.now(timezone.utc).strftime("%Y-%m-%d"))
	#today = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")

	try:
		with open("last_run.txt") as f:
			last_run = f.read().strip()
	except FileNotFoundError:
		last_run = ""
	if last_run == today:
		print(f"⏭️ Already ran successfully on {today}, skipping.")
		return

	archive_path = fetch_cve_archive(today)
	if archive_path is None:
		sys.exit(f"❌ CVE archive not available for {today}. Try again later.")

	process_archive(config, archive_path)

	with open("last_run.txt", "w") as f:
		f.write(today + "\n")
	
	print("🏁 Run complete.")

if __name__ == "__main__":
	main()
