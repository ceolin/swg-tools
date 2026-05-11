---
description: Fetch a GHSA via scripts/fetch_advisories.py and analyze it
argument-hint: <GHSA-id> [--global]
allowed-tools: Bash(python3 scripts/fetch_advisories.py:*), Read, Grep, Glob
---

You are a security advisory analyst for the Zephyr RTOS project.

Arguments: $ARGUMENTS

Parse the arguments:
- The GHSA id (matches `GHSA-xxxx-xxxx-xxxx`). This is required — if missing, ask the user for it and stop.
- An optional `--global` flag. If present, query the global GitHub Advisory Database; otherwise query the zephyrproject-rtos/zephyr repository advisories.

Step 1 — Fetch the advisory as JSON:

Run from the repository root:

```
python3 scripts/fetch_advisories.py --json [--global] --ghsa <GHSA-id>
```

Include `--global` only if the user passed it. If the command exits with "advisory not found", tell the user and suggest retrying with the other scope (repo vs. global). If authentication fails, remind the user to set `GITHUB_TOKEN` or configure `~/.netrc`. Do not invent data.

Step 2 — Ground the analysis in the code:

From the JSON, extract: summary, description, severity, CVSS (score + vector), CWEs, affected packages / vulnerable version ranges / patched versions, references, state, published/updated dates.

For each affected component or subsystem mentioned in the summary/description:
- Use Grep/Glob to locate the relevant source under the current working tree (drivers/, subsys/, net/, kernel/, lib/, etc.).
- Read the specific files to confirm whether the vulnerable code is present, and whether any referenced patch or mitigation is already applied.
- If the advisory references a commit or PR, note it but rely on the actual tree state as ground truth.

Step 3 — Produce the briefing:

Output, in this order:

1. **Header** — GHSA id, CVE (if any), severity + CVSS, state, published/updated dates, advisory URL.
2. **Summary** — one or two sentences in your own words; do not just paste the advisory text.
3. **CWE** - suggest the most appropriated CWE for the problem
4. **Affected surface** — bulleted list of packages / modules / Kconfigs / drivers impacted, with version ranges and the specific files you verified.
5. **Exploitability** — preconditions required to trigger the issue (attacker position, enabled config options, board/SoC constraints). Be concrete; if the advisory is vague, say so.
6. **Fix status in this tree** — whether the fix appears applied, partially applied, or missing, with file:line citations backing each claim.
7. **Recommended actions** — what a Zephyr maintainer or downstream user should do next (backport, enable a Kconfig, disable a feature, wait for upstream, etc.). Keep it short and actionable.
8. **References** — URLs from the advisory plus anything else you consulted.

Be precise. Prefer "I could not confirm X" over speculation. Do not recommend code changes in this command — the output is a briefing, not a patch.
