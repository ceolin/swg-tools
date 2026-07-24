# swg-tools

Tools for the Zephyr Project security working group.

## Contents

- `scripts/ghsa` — a single command-line tool for working with GitHub
  Security Advisories (GHSA) for `zephyrproject-rtos/zephyr`. It syncs
  advisories into a local database, browses them, generates advisory
  drafts from vulnerability reports, creates or updates them on GitHub, and renders
  an HTML dashboard.
- `ai-commands/` — prompt files for AI assistants that wrap the tool.

## Setup

Install dependencies into a project-local virtualenv:

```sh
uv sync
```

Run the tool via `uv run` so dependencies are resolved automatically:

```sh
uv run scripts/ghsa --help
```

## Authentication

Credentials are read from the environment (or `~/.netrc`); nothing is
stored in the repository.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` (or `~/.netrc` for `github.com`) | `sync`, `create`, `update` | GitHub API access |
| `OPENROUTER_API_KEY` | `generate` | OpenRouter LLM access |
| `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN` | `sync`, `list`, `show`, `dashboard` | optional remote Turso replica |
| `ZEPHYR_BASE` | `generate` | Zephyr checkout, for maintainer lookup |

## Commands

The tool reads from a local libSQL/Turso database (default
`advisories.db`); only `sync`, `create`, and `update` contact GitHub. Run `sync`
first to populate the database.

### `sync` — refresh the local database from GitHub

```sh
uv run scripts/ghsa sync
```

Fetches every advisory (all states) for the repository and upserts them
into the database, keyed by GHSA id.

### `list` — browse advisories

```sh
# Draft + triage advisories (default)
uv run scripts/ghsa list

# Only published advisories, as JSON
uv run scripts/ghsa list --state published --json

# Multiple states, filtered by severity
uv run scripts/ghsa list --state triage --state published --severity high

# Only advisories whose 90-day embargo has elapsed
uv run scripts/ghsa list --past-embargo

# Only advisories changed in the latest database sync
uv run scripts/ghsa list --synced

# Only advisories missing the Patches or For more information section
uv run scripts/ghsa list --missing-fields
```

### `show` — display a single advisory

```sh
uv run scripts/ghsa show GHSA-xxxx-xxxx-xxxx
uv run scripts/ghsa show GHSA-xxxx-xxxx-xxxx --json
```

### `generate` — draft an advisory from a report email

Sends a vulnerability report email to OpenRouter and produces a Markdown
advisory plus a GitHub API JSON payload. Maintainers of the affected
files (looked up via `$ZEPHYR_BASE/scripts/get_maintainer.py`) and the
`zephyrproject-rtos/security` team are added as collaborators.

```sh
# From a file, writing to ./advisories/
uv run scripts/ghsa generate --email report.eml

# From stdin, printed to stdout
cat report.eml | uv run scripts/ghsa generate --email - --stdout
```

### `create` — create a draft advisory on GitHub

Takes the JSON payload produced by `generate`:

```sh
uv run scripts/ghsa create advisories/<slug>-github.json
```

### `update` — update an advisory on GitHub

Adds the standard Patches and For more information sections when missing,
along with an embargo date calculated as 90 days after the advisory was
created. Existing fields are left unchanged.

```sh
uv run scripts/ghsa update GHSA-xxxx-xxxx-xxxx --missing-fields

# Preview the resulting advisory without updating GitHub
uv run scripts/ghsa update GHSA-xxxx-xxxx-xxxx --missing-fields --dry-run
```

### `dashboard` — render an HTML dashboard

Writes a single self-contained HTML file (inline CSS/SVG/JS, no external
assets) summarizing the database — stat tiles, severity/state/CWE/CVSS
charts, a created-over-time timeline, and a searchable, sortable table.

```sh
uv run scripts/ghsa dashboard --open
uv run scripts/ghsa dashboard -o report.html
```

See `uv run scripts/ghsa <command> --help` for the full option list of
any command.

## Syncing to a remote Turso database

The database is a local libSQL file (`--db`, default `advisories.db`).
If `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` are set, the file is
opened as an embedded [Turso](https://turso.tech) replica: reads pull
the latest data from the remote database, and `sync` pushes changes back
to it.

```sh
export TURSO_DATABASE_URL=libsql://<your-db>.turso.io
export TURSO_AUTH_TOKEN=<your-token>
uv run scripts/ghsa sync
```
