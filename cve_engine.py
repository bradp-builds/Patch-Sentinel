# cve_engine.py
import os
import json
import zipfile
import io
import fnmatch
from datetime import datetime, timezone, timedelta


class DBAdapter:
	"""Interface to abstract persistence operations between SQLite3 and Cloudflare D1"""

	def is_diff_processed(self, release_id: str) -> bool:
		raise NotImplementedError

	def mark_diff_processed(self, release_id: str):
		raise NotImplementedError

	def has_notified_today(self, cve_id: str, local_date: str) -> bool:
		raise NotImplementedError

	def record_notification(self, cve_id: str, local_date: str):
		raise NotImplementedError


def get_local_date(tz_name="America/Detroit"):
	"""Calculates the recipient's localized calendar day string (YYYY-MM-DD)"""
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


def process_zip_data(config, zip_bytes, db_adapter, send_notify_func):
	"""Unzips, scans delta logs, filters by stack pattern/score, and checks daily caps"""
	monitored_sources = config.get("monitored_sources", [])

	with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as outer_zip:
		# Hourly releases contain target CVE logs directly or inside a flat inner zip
		inner_zips = [name for name in outer_zip.namelist() if name.endswith(".zip")]
		zip_obj = (
			zipfile.ZipFile(io.BytesIO(outer_zip.read(inner_zips[0])), "r")
			if inner_zips
			else outer_zip
		)

		try:
			delta_paths = [
				name for name in zip_obj.namelist() if name.endswith("delta.json")
			]
			target_cves = set()

			if delta_paths:
				delta_data = json.loads(zip_obj.read(delta_paths[0]))
				for category in ["new", "updated"]:
					for item in delta_data.get(category, []):
						cve_id = item.get("cveId") if isinstance(item, dict) else item
						if cve_id:
							target_cves.add(cve_id)
			else:
				# Direct file-fallback if running from an unfiltered baseline
				for name in zip_obj.namelist():
					if name.endswith(".json") and not name.endswith("schema.json"):
						cve_id = os.path.splitext(os.path.basename(name))[0]
						if cve_id.startswith("CVE-"):
							target_cves.add(cve_id)

			if not target_cves:
				return

			cve_path_map = {
				os.path.splitext(os.path.basename(n))[0]: n
				for n in zip_obj.namelist()
				if n.endswith(".json")
			}
			local_date_str = get_local_date(config.get("timezone", "America/Detroit"))

			for cve_id in sorted(target_cves):
				filepath = cve_path_map.get(cve_id)
				if not filepath:
					continue

				try:
					cve_record = json.loads(zip_obj.read(filepath))
					cna = cve_record.get("containers", {}).get("cna", {})
					affected_nodes = cna.get("affected", [])
					descriptions = cna.get("descriptions", [])
					metrics = cna.get("metrics", [])

					desc_text = (
						descriptions[0].get("value", "No description provided")
						if descriptions
						else "No description provided"
					)

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
					if (
						min_score is not None
						and base_score is not None
						and base_score < min_score
					):
						continue

					matched = False
					matched_product = ""
					for node in affected_nodes:
						original_name = str(node.get("product", "") or "")
						if original_name and any(
							fnmatch.fnmatch(original_name.lower(), pat.lower())
							for pat in monitored_sources
						):
							matched = True
							matched_product = original_name
							break

					if not matched:
						for pattern in monitored_sources:
							if pattern.lower() in desc_text.lower():
								matched = True
								matched_product = pattern
								break

					if matched:
						# Apply local-day notification rate limit per individual CVE
						if db_adapter.has_notified_today(cve_id, local_date_str):
							print(
								f"ℹ️ {cve_id} already updated today ({local_date_str}). Suppressing duplicate spam."
							)
							continue

						send_notify_func(
							config, cve_id, matched_product, severity, desc_text
						)
						db_adapter.record_notification(cve_id, local_date_str)

				except Exception as e:
					print(f"⚠️ Skipping parsing error on {cve_id}: {e}")
					continue
		finally:
			if inner_zips:
				zip_obj.close()


def run_engine(config, db_adapter, fetch_func, send_notify_func):
	"""Evaluates the 24-hour lookback horizon and processes missing steps in order"""
	current_utc = datetime.now(timezone.utc)
	base_dt = current_utc.replace(minute=0, second=0, microsecond=0)

	lookback_releases = []
	for i in range(24, -1, -1):
		dt = base_dt - timedelta(hours=i)
		release_id = dt.strftime("%Y-%m-%d_%H00Z")
		lookback_releases.append((dt, release_id))

	unprocessed = [
		(dt, rid)
		for dt, rid in lookback_releases
		if not db_adapter.is_diff_processed(rid)
	]

	if not unprocessed:
		print("🏁 Processing pipeline is complete and up to date.")
		return

	is_test = config.get("test_mode", False)
	successful_count = 0
	max_successful = 3 if not is_test else len(unprocessed)

	for dt, release_id in unprocessed:
		if successful_count >= max_successful:
			break
		date_str = dt.strftime("%Y-%m-%d")
		hour_str = dt.strftime("%H")

		url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{date_str}_{hour_str}00Z/{date_str}_delta_CVEs_at_{hour_str}00Z.zip"
		zip_bytes = fetch_func(url)

		if zip_bytes is None:
			print(
				f"⚠️ Release data {release_id} not available yet (404). Will retry next run."
			)
			continue

		process_zip_data(config, zip_bytes, db_adapter, send_notify_func)
		db_adapter.mark_diff_processed(release_id)
		successful_count += 1
