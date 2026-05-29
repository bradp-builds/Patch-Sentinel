# Patch Sentinel

Monitor CVE publications for your software stack and get alerted via Discord — hourly, automated, zero-infrastructure.

## Features

- **Hourly CVE delta** — Fetches the official [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) hourly delta releases, processing only new and updated CVEs.
- **Product matching** — Glob pattern matching (e.g. `nginx*`, `linux`) against `containers.cna.affected[].product` in the CVE JSON schema. Falls back to description text when no product fields exist.
- **CVSS score filter** — Optional minimum severity threshold. CVEs with no CVSS score are **skipped** when a threshold is set.
- **Rich notifications** — Formatted alerts via Discord embeds.
- **Dual deployment modes** — Cloudflare Workers (production, env-var config) or local CLI runner (SQLite, YAML config) for testing.
- **Test mode** — Run with `--test` to print alerts to stdout instead of firing webhooks.
- **Safety cap** — Limits processing to 3 unprocessed hours by default; bypass with `-t`/`--test`.

## Prerequisites

- Python 3.x
- For local CLI: `pyyaml` (`pip install pyyaml`)

## Installation

```bash
git clone https://github.com/bradp-builds/patch-sentinel.git
cd patch-sentinel
```

## Deployment

### Cloudflare Workers (production)

Set these environment variables in your Workers dashboard or `wrangler.toml`:

| Variable | Required | Description |
|---|---|---|
| `PATCH_SENTINEL_PROVIDER` | Yes | Must be `"discord"` |
| `DISCORD_WEBHOOK_URL` | Yes | Discord webhook URL |
| `MIN_SEVERITY_SCORE` | No | Number 0–10 |
| `MONITORED_SOURCES` | No | Newline- or comma-separated globs |
| `TIMEZONE` | No | e.g. `America/Detroit` (default: UTC) |

Bind a D1 database named `DB` with the following schema (auto-created on first run):

```sql
CREATE TABLE IF NOT EXISTS processed_diffs (
  release_id TEXT PRIMARY KEY,
  processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sent_notifications (
  cve_id TEXT,
  local_date TEXT,
  notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (cve_id, local_date)
);
```

The worker runs on a cron schedule (configured via Workers dashboard).

### Local CLI (testing)

```bash
# File-based config
cp sample.config.yaml config.yaml
# edit config.yaml with your settings
python3 patch_sentinel.py

# Explicit config path
python3 patch_sentinel.py --config path/to/config.yaml

# Env-var mode
PATCH_SENTINEL_PROVIDER=discord \
  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... \
  MONITORED_SOURCES="linux,nginx*" \
  python3 patch_sentinel.py

# Test mode (print alerts to stdout, bypass safety cap)
python3 patch_sentinel.py --test
```

## How it works

1. Looks back up to 24 hours for unprocessed hourly delta releases.
2. Downloads each missing delta ZIP from the CVEProject releases: `https://github.com/CVEProject/cvelistV5/releases/download/cve_{date}_{hour}00Z/{date}_delta_CVEs_at_{hour}00Z.zip`
3. Extracts and parses all CVE JSON files from the ZIP, filtering to those published during that hour.
4. Matches product names against your `monitored_sources` patterns (case-insensitive `fnmatch`).
5. Filters by `min_severity_score` if configured (CVEs with no score are skipped when a threshold is set).
6. Sends a Discord webhook notification for each match — or prints to stdout in test mode.
7. Archives the release ID so it's not re-processed.
