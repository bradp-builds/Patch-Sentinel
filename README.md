# Patch Sentinel

Monitor CVE publications for your software stack and get alerted via Discord — hourly, with a small SQLite database and no server to maintain.

## Features

- **Hourly CVE delta** — Fetches the official [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) hourly delta releases, processing only new and updated CVEs.
- **Product matching** — Glob pattern matching (e.g. `nginx*`, `linux`) against `containers.cna.affected[].product` in the CVE JSON schema. Falls back to description text when no product fields exist.
- **CVSS score filter** — Optional minimum severity threshold. CVEs with no CVSS score are **skipped** when a threshold is set.
- **Rich notifications** — Formatted alerts via Discord embeds.
- **Automated execution** — GitHub Actions schedule (SQLite + `actions/cache`) or local CLI runner for testing.
- **Test mode** — Run with `--test` (or `TEST_MODE=true`) to print alerts to stdout instead of firing webhooks.

## Prerequisites

- Python 3.11+
- PyYAML for YAML configuration; environment-only execution uses the standard library.

## Installation

```bash
git clone https://github.com/bradp-builds/patch-sentinel.git
cd patch-sentinel
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Deployment

### GitHub Actions

Runs automatically on a schedule (default: every hour) or via manual trigger (`workflow_dispatch`).

Configure the following Repository Secrets / Variables in GitHub settings (`Settings > Secrets and variables > Actions`):

**Secrets:**
- `DISCORD_WEBHOOK_URL`: Your Discord webhook URL

**Variables:**
- `MIN_SEVERITY_SCORE`: Minimum CVSS threshold (e.g. `7.0`)
- `MONITORED_SOURCES`: Newline- or comma-separated glob patterns (e.g. `nginx*,linux`)
- `TIMEZONE`: e.g. `America/Detroit` (default: `UTC`)
- `TEST_MODE`: Set to `true` to print alerts to action logs instead of sending webhooks

The workflow runs `patch_sentinel.py` and uses GitHub Actions Cache to restore and save `local_db.sqlite`, including after partial failures. Runs are serialized. Cache storage is best effort: eviction or a failed save can lose state and cause repeat alerts. Keep the SQLite file on persistent storage when running elsewhere, and run only one process against a given database at a time.

### Local CLI (testing)

```bash
# File-based config
cp sample.config.yaml config.yaml
# edit config.yaml with your settings
python3 patch_sentinel.py

# Explicit config path
python3 patch_sentinel.py --config path/to/config.yaml

# Env-var mode
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... \
  MONITORED_SOURCES="linux,nginx*" \
  python3 patch_sentinel.py

# Test mode (print alerts to stdout)
python3 patch_sentinel.py --test
```

## Behavior

Each execution fixes a UTC discovery window at startup. Delivery timing advances with elapsed monotonic time, including time spent downloading:

1. Check hourly release timestamps in the inclusive interval `[now - 24 hours, now]`, skipping completed slots. This is normally 24 requests on first startup, or 25 exactly on an hour boundary; subsequent runs download only unprocessed slots.
2. A 404 stays pending until a later readable ZIP is available, then the earlier missing slot is retired. Other HTTP errors, truncated downloads and unreadable ZIPs remain retryable within the window. Downloads and decompressed records have size limits.
3. Parse CVEs and consider only publication timestamps in that same inclusive 24-hour interval. Missing, invalid and future timestamps do not qualify. Timestamps without an offset are interpreted as UTC. Record IDs must match their archive filenames.
4. Match product names using case-insensitive glob patterns. Only when product names are absent, fall back to description text, removing `*` and `?` from the pattern. Prefer an English description. Use the issuing authority's first valid CVSS base score in version order 4.0, 3.1, 3.0, then 2.0. If the authority provides no valid score, check CISA enrichment in the same order.
5. Apply the optional minimum CVSS score; missing scores do not qualify when a threshold is configured. Queue matches in SQLite before completing their release. Each alert gets 24 hours from its first enqueue time to be delivered. Later eligible versions can update its content without extending that deadline.
6. Deliver queued alerts with a five-minute delivery budget, reserving time for the next HTTP request. When a successful response exhausts the Discord bucket, pace the next request using `X-RateLimit-Reset-After`. On HTTP 429, use `Retry-After` or the JSON `retry_after` value and allow up to three retries per alert per run. Waits happen in chunks of at most 60 seconds. Longer cooldowns or an exhausted budget leave the remaining work queued; cooldowns are saved in SQLite and respected on subsequent runs. Unknown retry timing, authentication failures, connection failures and server errors stop the batch.
7. Record successful delivery and remove its pending entry in a single transaction. Suppress already delivered CVEs. Pending alerts expire at their delivery deadline or are removed when they no longer match product/score configuration. Once queued, publication age does not prevent delivery.

Malformed individual JSON/CVE records are logged and skipped, and make that run report an error. Their readable release is completed so an unchanged invalid record does not cause endless downloads. Malformed updates do not overwrite valid pending alerts. Unreadable archives remain retryable. Invalid pending records are reported and removed so one bad entry cannot block the queue.

The schedule can run late. Catch-up is capped at 24 hours regardless of outage duration. A CVE published yesterday may therefore alert today, but publications older than 24 hours are intentionally excluded from discovery. Already queued alerts can still be delivered after their publication leaves that window. Bookkeeping is retained for 48 hours, based on when releases were processed or notifications were recorded. Entries exactly 48 hours old remain until the next cleanup; pending alerts have a separate 24-hour delivery lifetime from first enqueue. Existing databases are migrated automatically, preserving release history, pending records and successful notifications. Older pending records have no enqueue timestamp, so migration gives them one delivery window beginning at migration time; reopening the database does not refresh it.

Delivery is best effort: a crash after Discord accepts a message but before SQLite records success can cause a duplicate on retry. Successful delivery cannot be made atomic across Discord and SQLite.

Test mode uses an in-memory database and does not change production state. It may print alerts previously delivered in production. `TIMEZONE` controls the publication timestamp displayed in Discord; eligibility always uses elapsed UTC time.

## Configuration and exit status

Configuration precedence is `--config`, then `PATCH_SENTINEL_CONFIG`, then environment mode when `DISCORD_WEBHOOK_URL` is present, then `config.yaml`. File and environment settings are not merged.

Unknown configuration keys are rejected with their names, so spelling mistakes cannot silently disable settings. Configuration is validated before downloads: at least one product pattern, a finite score from 0 to 10 when provided, `true`/`false` booleans, a valid IANA timezone and an HTTPS Discord webhook URL. Test mode permits an absent webhook. An empty environment timezone defaults to UTC. Missing timezone data may require installing your platform's timezone database.

Logs include a final count of downloads, missing and retired slots, invalid records, sent alerts, pending deliveries, expired alerts and errors. Expired alerts are logged explicitly rather than silently discarded. Webhook URLs are redacted, including in unexpected-error tracebacks.

| Exit code | Meaning |
| --- | --- |
| `0` | Completed without errors or pending deliveries; unpublished trailing 404s are normal. |
| `1` | Incomplete run, invalid upstream records, pending delivery, expired alerts, or an execution failure. Completed work remains saved. |
| `2` | Invalid configuration or command-line arguments. |

## Development

Tests are grouped by configuration, parsing, database, pipeline, delivery and HTTP/CLI, with shared fixtures in `tests/support.py`. The application stays in one module: configuration and normalized data models, pure parsing/filtering functions, SQLite and HTTP boundaries, then orchestration and CLI. It uses the standard library except for optional YAML input.

```bash
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
mypy
python -m unittest discover -s tests -v
```

CI runs these checks on Python 3.11 and 3.14. Tests mock HTTP and cover configuration, publication boundaries, malformed records, product/score filtering, missing releases, retry persistence, migration, atomic delivery bookkeeping, rate-limit pacing, delivery deadlines and secret redaction. Rate-limit tests use a fake clock and do not sleep. No live webhook is needed.
