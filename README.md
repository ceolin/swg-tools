# swg-tools

<p align="center">
  <img src="assets/swg-tools-mascot.png" alt="swg-tools kite mascot holding a security shield with a bandage" width="280">
</p>

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
| `SWG_GITHUB_TOKEN` (or `~/.netrc` for `github.com`) | `sync`, `create`, `update` | GitHub API access |
| `OPENROUTER_API_KEY` | `generate` | OpenRouter LLM access |
| `GHSA_DATABASE_URL` | `sync`, `list`, `show`, `update --analysis`, `dashboard` | shared MySQL database |
| `ZEPHYR_BASE` | `generate` | Zephyr checkout, for maintainer lookup |

## Commands

The tool reads from a shared MySQL database (see
[Database](#database)); only `sync`, `create`, and `update` contact GitHub. Run `sync`
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
uv run scripts/ghsa show GHSA-xxxx-xxxx-xxxx --open

# Only the stored analysis/triage notes, as Markdown
uv run scripts/ghsa show GHSA-xxxx-xxxx-xxxx --analysis > triage.md

# …or with its timestamp, as JSON
uv run scripts/ghsa show GHSA-xxxx-xxxx-xxxx --analysis --json
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

`--analysis` stores the contents of a Markdown file as the advisory's
analysis/triage notes in the local database (`analysis` column), stamping
the write time in `analysis_updated_at`. Both are local-only fields: they
are never sent to GitHub and are preserved across `sync`. Use `-` to read
from stdin, and `show` to read the notes back.

```sh
uv run scripts/ghsa update GHSA-xxxx-xxxx-xxxx --analysis triage.md
cat triage.md | uv run scripts/ghsa update GHSA-xxxx-xxxx-xxxx --analysis -
```

### `dashboard` — render an HTML dashboard

Writes a single self-contained HTML file (inline CSS/SVG/JS, no external
assets) summarizing the database — stat tiles, severity/state/CWE/CVSS
charts, a created-over-time timeline, and a searchable, sortable table.

The table's `Analysis` column links to the notes stored by
`update --analysis`; the link opens them in a new tab. The notes are
embedded in the HTML file, so the page stays self-contained.

```sh
uv run scripts/ghsa dashboard --open
uv run scripts/ghsa dashboard -o report.html
```

See `uv run scripts/ghsa <command> --help` for the full option list of
any command.

## Database

Advisories live in a central MySQL (or MariaDB) database so everyone on
the team works from the same data. Point the tool at it with a URL, either
in `GHSA_DATABASE_URL` or with `--db`:

```sh
export GHSA_DATABASE_URL='mysql://<user>:<password>@<host>[:port]/<database>'
uv run scripts/ghsa sync
```

Percent-encode special characters in the password (`@` is `%40`, `:` is
`%3A`). Append `?ssl=true` to require TLS with certificate verification
against the system CAs, or `?ssl_ca=/path/to/ca.pem` to use a specific CA.

`sync` creates the tables on first run. The database user needs
`SELECT`, `INSERT`, `UPDATE`, `CREATE` and `ALTER` on that database.

### Hosting the database

`deploy/mysql/` runs MySQL 8.4 in Docker with TLS required and a `ghsa`
account limited to the grants above. On the server:

```sh
cd deploy/mysql
./setup.sh db.example.org 203.0.113.10   # hostname, plus any other names/IPs
docker compose up -d
```

`setup.sh` generates random passwords in `secrets/` and a private CA plus
server certificate in `certs/`, then prints the `GHSA_DATABASE_URL` to
use. Clients must connect with one of the names given to `setup.sh` and
need a copy of `certs/ca.pem` for `?ssl_ca=`. Keep `certs/ca-key.pem` and
`secrets/` on the server only. Set `MYSQL_PORT` or `MYSQL_BIND` to change
the published port or listen address.

Restrict port 3306 to the team's addresses with the firewall, or keep it
off the internet and reach it over a VPN.

`backup.sh` writes a compressed dump to `backups/` and keeps 30 days
(`KEEP_DAYS`). Run it from cron and copy the dumps off the machine: the
analysis notes exist only in this database.

```sh
15 3 * * * /path/to/swg-tools/deploy/mysql/backup.sh
```
