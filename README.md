# swg-tools

Tools for the Zephyr Project security working group.

## Contents

- `scripts/fetch_advisories.py` — fetch security advisories from GitHub, either
  for a specific repository (default: `zephyrproject-rtos/zephyr`) or
  from the global GitHub Advisory Database.

## Setup

Install dependencies into a project-local virtualenv:

```sh
uv sync
```

## Authentication

A GitHub token is required for repository advisories. The token is
read from:

1. The `GITHUB_TOKEN` environment variable, or
2. `~/.netrc` for `github.com`.

## Usage

Run the script via `uv run` so dependencies are resolved automatically:

```sh
# Draft + triage advisories for zephyrproject-rtos/zephyr (default)
uv run scripts/fetch_advisories.py

# Only published advisories, JSON output
uv run scripts/fetch_advisories.py --state published --json

# Multiple explicit states
uv run scripts/fetch_advisories.py --state triage --state published

# A single advisory by GHSA id
uv run scripts/fetch_advisories.py --ghsa GHSA-xxxx-xxxx-xxxx
```

See `uv run scripts/fetch_advisories.py --help` for the full option list.

## Syncing to a local Turso database

`--sync-db` fetches every advisory (all states) and upserts them into a
local libSQL/Turso database, keyed by GHSA id:

```sh
uv run scripts/fetch_advisories.py --sync-db advisories.db
```

To also push the data to a remote
[Turso](https://turso.tech) database, open the local file as an embedded
replica by setting:

```sh
export TURSO_DATABASE_URL=libsql://<your-db>.turso.io
export TURSO_AUTH_TOKEN=<your-token>
uv run scripts/fetch_advisories.py --sync-db advisories.db
```
