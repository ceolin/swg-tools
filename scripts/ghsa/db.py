# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''Database operations for the local advisory store (libSQL / Turso).'''

import json
import os
import re
import sys
from datetime import date, datetime, timedelta
from typing import Any, Optional

DEFAULT_STATES = ('draft', 'triage')
ALL_STATES = ('draft', 'triage', 'published', 'closed')

PATCHES_RE = re.compile(r'(?ims)^#{1,6}\s*Patches\s*$\s*(.*?)(?=^#{1,6}\s|\Z)')

_CREATE_TABLE = '''\
CREATE TABLE IF NOT EXISTS advisories (
    ghsa_id      TEXT PRIMARY KEY,
    repo         TEXT,
    cve_id       TEXT,
    summary      TEXT,
    severity     TEXT,
    state        TEXT,
    cvss_score   REAL,
    cvss_vector  TEXT,
    cwes         TEXT,
    fixes        TEXT,
    html_url     TEXT,
    created_at   TEXT,
    published_at TEXT,
    updated_at   TEXT,
    embargo      TEXT,
    raw          TEXT NOT NULL,
    synced_at    TEXT NOT NULL
)'''

_UPSERT = '''\
INSERT INTO advisories (
    ghsa_id, repo, cve_id, summary, severity, state, cvss_score,
    cvss_vector, cwes, fixes, html_url, created_at, published_at,
    updated_at, embargo, raw, synced_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ghsa_id) DO UPDATE SET
    repo         = excluded.repo,
    cve_id       = excluded.cve_id,
    summary      = excluded.summary,
    severity     = excluded.severity,
    state        = excluded.state,
    cvss_score   = excluded.cvss_score,
    cvss_vector  = excluded.cvss_vector,
    cwes         = excluded.cwes,
    fixes        = excluded.fixes,
    html_url     = excluded.html_url,
    created_at   = excluded.created_at,
    published_at = excluded.published_at,
    updated_at   = excluded.updated_at,
    embargo      = excluded.embargo,
    raw          = excluded.raw,
    synced_at    = excluded.synced_at'''


# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_embargo(created_at: str) -> str:
    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
    return (dt + timedelta(days=90)).strftime('%Y-%m-%d')


def parse_patches(description: Optional[str]) -> Optional[str]:
    if not description:
        return None
    m = PATCHES_RE.search(description)
    if not m:
        return None
    return m.group(1).strip() or None


def parse_fixes(description: Optional[str]) -> list[str]:
    patches = parse_patches(description)
    if not patches:
        return []
    fixes: list[str] = []
    for line in patches.splitlines():
        line = re.sub(r'^\s*(?:[-*+]|\d+\.)\s+', '', line).strip()
        if line:
            fixes.append(line)
    return fixes


def _advisory_row(a: dict[str, Any], repo: str,
                  synced_at: str) -> tuple[Any, ...]:
    cvss = a.get('cvss') or {}
    cwes = [c.get('cwe_id') for c in (a.get('cwes') or []) if c.get('cwe_id')]
    fixes = parse_fixes(a.get('description'))
    created_at = a.get('created_at')
    return (
        a.get('ghsa_id'),
        repo,
        a.get('cve_id'),
        a.get('summary'),
        (a.get('severity') or '').lower() or None,
        a.get('state'),
        cvss.get('score'),
        cvss.get('vector_string'),
        json.dumps(cwes) if cwes else None,
        json.dumps(fixes) if fixes else None,
        a.get('html_url'),
        created_at,
        a.get('published_at'),
        a.get('updated_at'),
        get_embargo(created_at) if created_at else None,
        json.dumps(a, sort_keys=True),
        synced_at,
    )


# ─── Connection ──────────────────────────────────────────────────────────────

def turso_credentials() -> tuple[Optional[str], Optional[str]]:
    return (os.environ.get('TURSO_DATABASE_URL'),
            os.environ.get('TURSO_AUTH_TOKEN'))


def connect_db(db_path: str) -> Any:
    '''Open the local libSQL database, syncing from Turso if configured.'''
    try:
        import libsql
    except ImportError:
        sys.exit('error: the "libsql" package is required (uv add libsql)')

    sync_url, auth_token = turso_credentials()
    if sync_url:
        conn = libsql.connect(db_path, sync_url=sync_url, auth_token=auth_token)
        conn.sync()
        return conn
    return libsql.connect(db_path)


def has_advisories_table(conn: Any) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='advisories'"
    ).fetchone()
    return row is not None


# ─── Write ───────────────────────────────────────────────────────────────────

def sync_to_db(db_path: str, repo: str,
               advisories: list[dict[str, Any]]) -> int:
    '''Upsert advisories into the local database, then push to Turso.'''
    conn = connect_db(db_path)
    conn.execute(_CREATE_TABLE)
    synced_at = datetime.now().astimezone().isoformat()
    count = 0
    for a in advisories:
        if not a.get('ghsa_id'):
            continue
        conn.execute(_UPSERT, _advisory_row(a, repo, synced_at))
        count += 1
    conn.commit()
    if turso_credentials()[0]:
        conn.sync()
    return count


# ─── Read ────────────────────────────────────────────────────────────────────

def query_advisories(conn: Any, repo: str, states: list[str],
                     severity: Optional[str],
                     past_embargo: bool) -> list[dict[str, Any]]:
    clauses = ['repo = ?']
    params: list[Any] = [repo]
    if states:
        placeholders = ', '.join('?' for _ in states)
        clauses.append(f'state IN ({placeholders})')
        params.extend(states)
    if severity:
        clauses.append('severity = ?')
        params.append(severity.lower())
    if past_embargo:
        clauses.append('embargo IS NOT NULL AND embargo < ?')
        params.append(date.today().isoformat())
    sql = ('SELECT raw FROM advisories WHERE ' + ' AND '.join(clauses)
           + ' ORDER BY created_at DESC')
    rows = conn.execute(sql, params).fetchall()
    return [json.loads(r[0]) for r in rows]


def get_advisory(conn: Any, ghsa_id: str) -> dict[str, Any]:
    row = conn.execute(
        'SELECT raw FROM advisories WHERE ghsa_id = ?', (ghsa_id,)
    ).fetchone()
    if row is None:
        sys.exit(f'error: advisory {ghsa_id} not found in the local database')
    return json.loads(row[0])
