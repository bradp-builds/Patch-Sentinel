# Patch Sentinel

Monitor CVE publications for your software stack and get alerted via Discord — hourly, automated, zero-infrastructure.

## Features

- **Hourly CVE delta** — Fetches the official [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) hourly delta releases, processing only new and updated CVEs.
- **Product matching** — Glob pattern matching (e.g. `nginx*`, `linux`) against `containers.cna.affected[].product` in the CVE JSON schema. Falls back to description text when no product fields exist.
- **CVSS score filter** — Optional minimum severity threshold. CVEs with no CVSS score are **skipped** when a threshold is set.
- **Rich notifications** — Formatted alerts via Discord embeds.
- **Automated execution** — GitHub Actions schedule (SQLite + `actions/cache`) or local CLI runner for testing.
- **Test mode** — Run with `--test` (or `TEST_MODE=true`) to print alerts to stdout instead of firing webhooks.

## Prerequisites

- Python 3.x
- For local YAML config CLI: `pyyaml` (`pip install pyyaml`)

## Installation

```bash
git clone https://github.com/bradp-builds/patch-sentinel.git
cd patch-sentinel
```

## Deployment

### GitHub Actions

Runs automatically on a schedule (default: every 12 hours) or via manual trigger (`workflow_dispatch`).

Configure the following Repository Secrets / Variables in GitHub settings (`Settings > Secrets and variables > Actions`):

**Secrets:**
- `DISCORD_WEBHOOK_URL`: Your Discord webhook URL

**Variables:**
- `PATCH_SENTINEL_PROVIDER`: Defaults to `"discord"`
- `MIN_SEVERITY_SCORE`: Minimum CVSS threshold (e.g. `7.0`)
- `MONITORED_SOURCES`: Newline- or comma-separated glob patterns (e.g. `nginx*,linux`)
- `TIMEZONE`: e.g. `America/Detroit` (default: `UTC`)
- `TEST_MODE`: Set to `true` to print alerts to action logs instead of sending webhooks

The workflow runs `patch_sentinel.py` and uses GitHub Actions Cache (`actions/cache`) to persist state (`local_db.sqlite`) across runs without committing to the repository.

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

# Test mode (print alerts to stdout)
python3 patch_sentinel.py --test
```

## How it works

1. Looks back up to 7 days for unprocessed hourly delta releases.
2. Downloads each missing delta ZIP from the CVEProject releases: `https://github.com/CVEProject/cvelistV5/releases/download/cve_{date}_{hour}00Z/{date}_delta_CVEs_at_{hour}00Z.zip`
3. Extracts and parses all CVE JSON files from the ZIP, filtering to those published during that hour.
4. Matches product names against your `monitored_sources` patterns (case-insensitive `fnmatch`).
5. Filters by `min_severity_score` if configured (CVEs with no score are skipped when a threshold is set).
6. Sends a Discord webhook notification for each match — or prints to stdout in test mode.
7. Archives the release ID in SQLite so it's not re-processed.
