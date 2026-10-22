# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''Database operations for the shared advisory store (MySQL).'''

import json
import re
import sys
from urllib.parse import parse_qs, unquote, urlsplit
from datetime import date, datetime, timedelta
from typing import Any, Optional

DEFAULT_STATES = ('draft', 'triage')
ALL_STATES = ('draft', 'triage', 'published', 'closed')

PATCHES_RE = re.compile(r'(?ims)^#{1,6}\s*Patches\s*$\s*(.*?)(?=^#{1,6}\s|\Z)')

_CREATE_TABLE = '''\
CREATE TABLE IF NOT EXISTS advisories (
    ghsa_id      VARCHAR(64) NOT NULL PRIMARY KEY,
    repo         VARCHAR(255),
    cve_id       VARCHAR(32),
    summary      TEXT,
    severity     VARCHAR(16),
    state        VARCHAR(16),
    cvss_score   DOUBLE,
    cvss_vector  VARCHAR(255),
    cwes         TEXT,
    fixes        TEXT,
    html_url     VARCHAR(512),
    created_at   VARCHAR(40),
    published_at VARCHAR(40),
    updated_at   VARCHAR(40),
    embargo      VARCHAR(10),
    analysis     LONGTEXT,
    analysis_updated_at VARCHAR(40),
    raw          LONGTEXT NOT NULL,
    synced_at    VARCHAR(40) NOT NULL,
    INDEX idx_advisories_repo (repo)
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin'''

# Columns added after the initial schema; applied to existing databases by
# ensure_schema().
_EXTRA_COLUMNS = (
    ('analysis', 'LONGTEXT'),
    ('analysis_updated_at', 'VARCHAR(40)'),
)

_CREATE_SYNC_METADATA_TABLE = '''\
CREATE TABLE IF NOT EXISTS sync_metadata (
    name      VARCHAR(64) NOT NULL PRIMARY KEY,
    synced_at VARCHAR(40) NOT NULL
) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin'''

_UPSERT_COLUMNS = (
    'ghsa_id', 'repo', 'cve_id', 'summary', 'severity', 'state', 'cvss_score',
    'cvss_vector', 'cwes', 'fixes', 'html_url', 'created_at', 'published_at',
    'updated_at', 'embargo', 'raw', 'synced_at',
)

# Only overwrite a row when GitHub reports a newer updated_at. MySQL applies
# the assignments left to right, so updated_at must be assigned last: the
# condition reads the stored value and would see the new one otherwise.
_NEWER = ('VALUES(updated_at) IS NOT NULL AND (updated_at IS NULL '
          'OR VALUES(updated_at) > updated_at)')
_UPSERT = (
    'INSERT INTO advisories (' + ', '.join(_UPSERT_COLUMNS) + ') VALUES ('
    + ', '.join('%s' for _ in _UPSERT_COLUMNS) + ')\n'
    'ON DUPLICATE KEY UPDATE\n    '
    + ',\n    '.join(
        f'{col} = IF({_NEWER}, VALUES({col}), {col})'
        for col in [c for c in _UPSERT_COLUMNS if c not in
                    ('ghsa_id', 'updated_at')] + ['updated_at']))

_UPSERT_GLOBAL_SYNCED_AT = '''\
INSERT INTO sync_metadata (name, synced_at)
VALUES ('global', %s)
ON DUPLICATE KEY UPDATE
    synced_at = VALUES(synced_at)'''

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
    patches = m.group(1).strip()
    if not patches:
        return None

    table_separator_seen = False
    for line in patches.splitlines():
        cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
        if len(cells) < 2:
            continue
        if all(re.fullmatch(r':?-{3,}:?', cell) for cell in cells):
            table_separator_seen = True
            continue
        if table_separator_seen and any(cells):
            return patches

    return None


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

DATABASE_URL_ENV = 'GHSA_DATABASE_URL'


def redact_url(db_url: str) -> str:
    '''Return the database URL with the password masked, for messages.'''
    parts = urlsplit(db_url)
    if parts.password is None:
        return db_url
    netloc = parts.netloc.replace(f':{parts.password}@', ':***@', 1)
    return parts._replace(netloc=netloc).geturl()


def _connect_args(db_url: str) -> dict[str, Any]:
    '''Translate mysql://user:pass@host:port/dbname?ssl=true into PyMySQL
    connect() keyword arguments.'''
    parts = urlsplit(db_url)
    if parts.scheme not in ('mysql', 'mysql+pymysql'):
        sys.exit(f'error: unsupported database URL {redact_url(db_url)}; '
                 'expected mysql://user:password@host[:port]/database')
    database = parts.path.lstrip('/')
    if not parts.hostname or not database:
        sys.exit(f'error: database URL {redact_url(db_url)} must name a host '
                 'and a database')
    args: dict[str, Any] = {
        'host': parts.hostname,
        'port': parts.port or 3306,
        'user': unquote(parts.username or ''),
        'password': unquote(parts.password or ''),
        'database': database,
        'charset': 'utf8mb4',
    }
    query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
    if query.get('ssl_ca'):
        args['ssl_ca'] = query['ssl_ca']
    if query.get('ssl', '').lower() in ('1', 'true', 'yes') or 'ssl_ca' in args:
        args['ssl_verify_cert'] = True
        args['ssl_verify_identity'] = True
    return args


def connect_db(db_url: Optional[str]) -> Any:
    '''Open a connection to the shared MySQL database.'''
    if not db_url:
        sys.exit(f'error: no database configured; set {DATABASE_URL_ENV} or '
                 'pass --db mysql://user:password@host/database')
    try:
        import pymysql
    except ImportError:
        sys.exit('error: the "pymysql" package is required (uv add pymysql)')
    try:
        return pymysql.connect(**_connect_args(db_url))
    except (pymysql.Error, OSError) as exc:
        sys.exit(f'error: cannot connect to {redact_url(db_url)}: {exc}')


def _execute(conn: Any, sql: str, params: Any = None) -> Any:
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur


def _has_table(conn: Any, name: str) -> bool:
    row = _execute(
        conn,
        'SELECT 1 FROM information_schema.tables '
        'WHERE table_schema = DATABASE() AND table_name = %s', (name,)
    ).fetchone()
    return row is not None


def has_advisories_table(conn: Any) -> bool:
    return _has_table(conn, 'advisories')


def has_sync_metadata_table(conn: Any) -> bool:
    return _has_table(conn, 'sync_metadata')


def _columns(conn: Any) -> set[str]:
    return {row[0] for row in _execute(
        conn,
        'SELECT column_name FROM information_schema.columns '
        "WHERE table_schema = DATABASE() AND table_name = 'advisories'"
    ).fetchall()}


def ensure_schema(conn: Any) -> None:
    '''Add columns introduced after a database was first created.'''
    if not has_advisories_table(conn):
        return
    existing = _columns(conn)
    for name, decl in _EXTRA_COLUMNS:
        if name not in existing:
            _execute(conn, f'ALTER TABLE advisories ADD COLUMN {name} {decl}')
            conn.commit()


# ─── Write ───────────────────────────────────────────────────────────────────

def sync_to_db(db_url: Optional[str], repo: str,
               advisories: list[dict[str, Any]]) -> int:
    '''Upsert advisories into the database.'''
    conn = connect_db(db_url)
    _execute(conn, _CREATE_TABLE)
    _execute(conn, _CREATE_SYNC_METADATA_TABLE)
    ensure_schema(conn)
    synced_at = datetime.now().astimezone().isoformat()
    count = 0
    for a in advisories:
        if not a.get('ghsa_id'):
            continue
        # Affected rows: 1 for an insert, 2 for an update, 0 when unchanged.
        if _execute(conn, _UPSERT, _advisory_row(a, repo, synced_at)).rowcount:
            count += 1
    if count:
        _execute(conn, _UPSERT_GLOBAL_SYNCED_AT, (synced_at,))
    conn.commit()
    return count


def set_analysis(db_url: Optional[str], ghsa_id: str,
                 analysis: Optional[str]) -> Optional[str]:
    '''Store the triage/analysis text of an advisory.

    Returns the timestamp recorded alongside it (None when clearing).
    '''
    conn = connect_db(db_url)
    if not has_advisories_table(conn):
        sys.exit('error: no advisories in the database; run `ghsa sync` first')
    ensure_schema(conn)
    if _execute(conn, 'SELECT 1 FROM advisories WHERE ghsa_id = %s',
                (ghsa_id,)).fetchone() is None:
        sys.exit(f'error: advisory {ghsa_id} not found in the database')
    updated_at = datetime.now().astimezone().isoformat() if analysis else None
    _execute(conn,
             'UPDATE advisories SET analysis = %s, analysis_updated_at = %s '
             'WHERE ghsa_id = %s', (analysis, updated_at, ghsa_id))
    conn.commit()
    return updated_at


# ─── Read ────────────────────────────────────────────────────────────────────

def _select_columns(conn: Any) -> tuple[str, list[str]]:
    '''Build the select list for reads: raw, embargo, plus any extra column
    already present in this database.'''
    existing = _columns(conn)
    extra = [name for name, _ in _EXTRA_COLUMNS if name in existing]
    return ', '.join(['raw', 'embargo'] + extra), extra


def _hydrate(row: tuple[Any, ...], extra: list[str]) -> dict[str, Any]:
    '''Turn a selected row into an advisory dict.'''
    advisory = json.loads(row[0])
    if row[1] and not advisory.get('embargo'):
        advisory['embargo'] = row[1]
    for name, value in zip(extra, row[2:]):
        if value:
            advisory[name] = value
    return advisory


def query_advisories(conn: Any, repo: str, states: list[str],
                     severity: Optional[str],
                     past_embargo: bool,
                     synced_since_global: bool = False) -> list[dict[str, Any]]:
    clauses = ['repo = %s']
    params: list[Any] = [repo]
    if synced_since_global:
        if not has_sync_metadata_table(conn):
            return []
        row = _execute(
            conn, 'SELECT synced_at FROM sync_metadata WHERE name = %s',
            ('global',)
        ).fetchone()
        if row is None:
            return []
        clauses.append('synced_at >= %s')
        params.append(row[0])
    if states:
        placeholders = ', '.join('%s' for _ in states)
        clauses.append(f'state IN ({placeholders})')
        params.extend(states)
    if severity:
        clauses.append('severity = %s')
        params.append(severity.lower())
    if past_embargo:
        clauses.append('embargo IS NOT NULL AND embargo < %s')
        params.append(date.today().isoformat())
    columns, extra = _select_columns(conn)
    sql = (f'SELECT {columns} FROM advisories WHERE ' + ' AND '.join(clauses)
           + ' ORDER BY created_at DESC')
    rows = _execute(conn, sql, params).fetchall()
    return [_hydrate(row, extra) for row in rows]


def get_advisory(conn: Any, ghsa_id: str) -> dict[str, Any]:
    columns, extra = _select_columns(conn)
    row = _execute(
        conn, f'SELECT {columns} FROM advisories WHERE ghsa_id = %s',
        (ghsa_id,)
    ).fetchone()
    if row is None:
        sys.exit(f'error: advisory {ghsa_id} not found in the database')
    return _hydrate(row, extra)
