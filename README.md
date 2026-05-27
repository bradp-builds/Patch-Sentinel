# Patch Sentinel

Monitor CVE publications for your software stack and get alerted via Discord or Slack — daily, automated, zero-infrastructure.

## Features

- **Daily CVE delta** — Fetches the official [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) archive each day, processing only new and updated CVEs.
- **Product matching** — Glob pattern matching (e.g. `nginx*`, `linux`) against `containers.cna.affected[].product` in the CVE JSON schema. Falls back to description text when product is empty.
- **CVSS score filter** — Optional minimum severity threshold. CVEs with no CVSS score always pass through.
- **Rich notifications** — Formatted alerts via Discord embeds or Slack blocks.
- **Dual config modes** — YAML file for local use, environment variables for CI (GitHub Actions).
- **Test mode** — Run with `--test` to print alerts to stdout instead of firing webhooks.
- **Lightweight** — Single Python file, no pip dependencies.

## Prerequisites

- Python 3.x

## Installation

```bash
git clone https://github.com/bradp-builds/patch-sentinel.git
cd patch-sentinel
```

## Configuration

Two mutually exclusive modes. When `PATCH_SENTINEL_PROVIDER` is set in the environment, the config file is **ignored entirely**.

### File-based config

Copy `sample.config.yaml` to `config.yaml` and fill in your settings:

```yaml
notification_provider: "discord"

providers:
  discord:
    webhook_url: "https://discord.com/api/webhooks/..."
  slack:
    webhook_url: "https://hooks.slack.com/services/..."

min_severity_score: 6.0

monitored_sources:
  - "linux"
  - "nginx*"
```

> `config.yaml` is gitignored (contains webhook URLs). `sample.config.yaml` is the template.

### Env-var config (GitHub Actions / CI)

Set `PATCH_SENTINEL_PROVIDER` to enable this mode. Use `-t`/`--test` on the CLI to enable test mode.

| Variable | Required | Description |
|---|---|---|
| `PATCH_SENTINEL_PROVIDER` | Yes | `"discord"` or `"slack"` |
| `DISCORD_WEBHOOK_URL` | Per provider | Discord webhook URL |
| `SLACK_WEBHOOK_URL` | Per provider | Slack webhook URL |
| `MIN_SEVERITY_SCORE` | No | Number 0–10 |
| `MONITORED_SOURCES` | No | Newline- or comma-separated globs |
| `PATCH_SENTINEL_CONFIG` | No | Config file path (default: `config.yaml`). Ignored when `--config` is given. |


## Usage

```bash
# File-based config
python3 patch_sentinel.py
python3 patch_sentinel.py --config path/to/config.yaml

# Env-var mode
PATCH_SENTINEL_PROVIDER=discord \
  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... \
  MONITORED_SOURCES="linux,nginx*" \
  python3 patch_sentinel.py
```

## GitHub Actions

This repository includes a pre-built workflow at `.github/workflows/schedule.yml`. Fork the repo and set the following in your copy:

**Secrets** (repo → Settings → Secrets and variables → Actions):
- `DISCORD_WEBHOOK_URL`
- `SLACK_WEBHOOK_URL`

**Variables** (same page, Variables tab):
- `PATCH_SENTINEL_PROVIDER` — `"discord"` or `"slack"`
- `MIN_SEVERITY_SCORE` — e.g. `6.0`
- `MONITORED_SOURCES` — newline-separated patterns

The workflow:
- Runs twice daily (08:00 and 20:00 UTC)
- Runs Patch Sentinel, then commits `last_run.txt` if successful


## How it works

1. Downloads the daily double-zipped archive (`.zip.zip`) from the CVEProject releases.
2. Extracts `delta.json` listing CVE IDs that are new or updated.
3. Parses only the changed CVE JSON files.
4. Matches product names against your `monitored_sources` patterns (case-insensitive `fnmatch`).
5. Filters by `min_severity_score` if configured.
6. Sends a webhook notification for each match — or prints to stdout in test mode.
