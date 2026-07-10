## Template for a Zephyr RTOS GHSA Advisory

The advisory document must follow this exact structure.  Replace every
`<PLACEHOLDER>` with content derived from the vulnerability report.  Do not
add or remove top-level sections.

---

<ONE OR TWO PARAGRAPHS describing the root cause, the vulnerable code path,
how the overflow / bug manifests, what an attacker must do to trigger it, what
the impact is (crash, OOB write, potential code execution, …), and how the fix
addresses it.  Be concrete — cite driver names, function names, Kconfig
symbols, and file paths as they appear in the report.>

### Affected components
- `<path/to/affected/file.c>` [add more bullet points if needed]

### Affected versions
<version range description; e.g. "v4.3.0 through v4.4.0 (…); fixed on main by <short-sha>">

### Fix

<Proposed fix from the email. Only add it if it is part of the report>

### Evidence
- <file>:<line> — <one-line explanation>
[repeat for each key code location]
