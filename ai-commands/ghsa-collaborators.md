---
description: Add GHSA collaborators
argument-hint: <GHSA-id> [--global]
allowed-tools: Bash(python3 scripts/ghsa:*), Bash(.venv/bin/python3:*), Bash(python3 scripts/update_collaborators.py:*), Read, Grep, Glob, Write
---



Arguments: $ARGUMENTS

Parse the arguments:
- The GHSA id (matches `GHSA-xxxx-xxxx-xxxx`). This is required — if missing, ask the user for it and stop.
- An optional `--global` flag. If present, query the global GitHub Advisory Database; otherwise query the zephyrproject-rtos/zephyr repository advisories.

## Environment notes (read first)

The `ghsa` package and `get_maintainer.py` have third-party dependencies that
are usually not on the bare system `python3`. Use the right interpreter or the
commands fail with `ModuleNotFoundError`:

- `scripts/ghsa` needs `click` (and `requests`). Run it with this repo's
  virtualenv: `.venv/bin/python3 scripts/ghsa ...`.
- `$ZEPHYR_BASE/scripts/get_maintainer.py` needs `tabulate` and `PyYAML`, which
  live in the zephyrproject workspace venv, not this repo's `.venv`. Run it with
  `$ZEPHYR_BASE/../.venv/bin/python3` (i.e. the `.venv`
  next to `$ZEPHYR_BASE`).

## Step 1 — Fetch the advisory as JSON

Run from the repository root:

```
.venv/bin/python3 scripts/ghsa show --json <GHSA-id>
```

If the command exits with "advisory not found", tell the user to run
`.venv/bin/python3 scripts/ghsa sync` first to populate the local database
(requires `GITHUB_TOKEN` or `~/.netrc`). Do not invent data.

From the JSON, note these fields — they are needed later:
- `summary` and `description` (used to find affected files in Step 2).
- `collaborating_teams` and `collaborating_users` — the collaborators **already
  attached** to the advisory. Each `collaborating_users` entry is a user object;
  the handle is its `login`. Keep these: the PATCH in Step 4 **replaces** the
  lists rather than appending, so anyone omitted would be dropped.

## Step 2 — Analyze the advisory and find affected files

From the `summary`/`description`, list every affected source file or subsystem
(the description usually cites concrete paths, e.g.
`subsys/bluetooth/audio/bap_broadcast_sink.c`).

For each affected file run:

```
$ZEPHYR_BASE/../.venv/bin/python3 $ZEPHYR_BASE/scripts/get_maintainer.py path <file>
```

Collect the `maintainers:` handles only. **Ignore the `collaborators:` line** —
those are Zephyr code-area collaborators, not GHSA advisory collaborators.
Deduplicate across all affected files.

## Step 3 — Produce the collaborators JSON

Write a JSON file to `advisories/<GHSA-id>-collaborators.json` with the payload
the GitHub advisory PATCH endpoint accepts:

```json
{
  "collaborating_teams": ["security"],
  "collaborating_users": ["<existing-collaborator-logins>", "<maintainer-handles>"]
}
```

Rules:
- Always include the `security` team in `collaborating_teams` (and keep any teams
  the advisory already had).
- `collaborating_users` must be the **union** of:
  1. every `login` already in the advisory's `collaborating_users` (from Step 1), and
  2. the maintainer handles gathered in Step 2.
  Deduplicate, preserving existing entries first. Never drop a collaborator that
  was already listed — the PATCH replaces the list wholesale.

## Step 4 — Apply the update (optional)

`scripts/update_collaborators.py` PATCHes the advisory on GitHub from the JSON
file. It forwards only the `collaborating_teams`/`collaborating_users` fields and
needs a token with write access to security advisories (`GITHUB_TOKEN` or
`~/.netrc`). Dry-run first:

```
.venv/bin/python3 scripts/update_collaborators.py <GHSA-id> advisories/<GHSA-id>-collaborators.json --dry-run
```

Drop `--dry-run` to actually push the change.
