#!/usr/bin/env python3
# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

'''
Fetch security advisories from GitHub using the REST API.

This lists repository security advisories for zephyrproject-rtos/zephyr.

Authentication:
    A GitHub token is required for repository advisories. The token is
    read from the GITHUB_TOKEN environment variable, or ~/.netrc for
    github.com.

Examples:
    # Draft + triage advisories for zephyrproject-rtos/zephyr (default)
    ./fetch_advisories.py

    # Only published advisories, JSON output
    ./fetch_advisories.py --state published --json

    # Fetch multiple explicit states
    ./fetch_advisories.py --state triage --state published

    # Fetch a single advisory by GHSA id
    ./fetch_advisories.py --ghsa GHSA-xxxx-xxxx-xxxx

    # Sync every advisory (all states) into a local Turso/libSQL database
    ./fetch_advisories.py --sync-db advisories.db

Turso sync:
    --sync-db writes to a local libSQL database file. If the
    TURSO_DATABASE_URL and TURSO_AUTH_TOKEN environment variables are
    set, the local file is opened as an embedded replica and changes are
    pushed to the remote Turso database after the sync.
'''

import argparse
import json
import netrc
import os
import re
import sys
from datetime import date, datetime, timedelta
from typing import Any, Iterator, Optional

import requests

GITHUB_API = 'https://api.github.com'
DEFAULT_REPO = 'zephyrproject-rtos/zephyr'


def get_token() -> Optional[str]:
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        return token
    try:
        nrc = netrc.netrc()
    except (FileNotFoundError, netrc.NetrcParseError):
        return None
    auth = nrc.authenticators('github.com')
    if auth is not None:
        return auth[2]
    return None


def paginate(session: requests.Session, url: str,
             params: dict[str, Any]) -> Iterator[dict[str, Any]]:
    '''Yield items from a paginated GitHub list endpoint.'''
    params = dict(params)
    params.setdefault('per_page', 100)
    while url:
        resp = session.get(url, params=params)
        if resp.status_code == 401:
            sys.exit('error: authentication failed; check your GitHub token')
        if resp.status_code == 403 and 'rate limit' in resp.text.lower():
            sys.exit('error: GitHub API rate limit exceeded')
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            sys.exit(f'error: unexpected response: {data}')
        yield from data
        url = resp.links.get('next', {}).get('url')
        # Parameters are already encoded in the `next` URL.
        params = {}


DEFAULT_STATES = ('draft', 'triage')
ALL_STATES = ('draft', 'triage', 'published', 'closed')

def get_embargo(created_at: str) -> str:
    embargo = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
    return (embargo + timedelta(days=90)).strftime('%Y-%m-%d')


def is_past_embargo(created_at: Optional[str]) -> bool:
    if not created_at:
        return False
    return date.fromisoformat(get_embargo(created_at)) < date.today()


def filter_past_embargo(
        advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [a for a in advisories if is_past_embargo(a.get('created_at'))]


def fetch_repo_advisories(session: requests.Session, repo: str,
                          states: list[str]) -> list[dict[str, Any]]:
    # The GitHub API accepts only one state per call, so fetch each
    # requested state separately and concatenate.
    url = f'{GITHUB_API}/repos/{repo}/security-advisories'
    result: list[dict[str, Any]] = []
    for state in states:
        result.extend(paginate(session, url, {'state': state}))
    return result


def fetch_advisory(session: requests.Session, ghsa: str,
                   repo: str) -> dict[str, Any]:
    url = f'{GITHUB_API}/repos/{repo}/security-advisories/{ghsa}'
    resp = session.get(url)
    if resp.status_code == 401:
        sys.exit('error: authentication failed; check your GitHub token')
    if resp.status_code == 404:
        sys.exit(f'error: advisory {ghsa} not found')
    if resp.status_code == 403 and 'rate limit' in resp.text.lower():
        sys.exit('error: GitHub API rate limit exceeded')
    resp.raise_for_status()
    return resp.json()


def filter_severity(advisories: list[dict[str, Any]],
                    severity: str) -> list[dict[str, Any]]:
    return [a for a in advisories
            if (a.get('severity') or '').lower() == severity.lower()]


PATCHES_RE = re.compile(r'(?ims)^#{1,6}\s*Patches\s*$\s*(.*?)(?=^#{1,6}\s|\Z)')


def parse_patches(description: Optional[str]) -> Optional[str]:
    if not description:
        return None
    m = PATCHES_RE.search(description)
    if not m:
        return None
    return m.group(1).strip() or None


def print_advisory(a: dict[str, Any]) -> None:
    def field(name: str, value: Any) -> None:
        if value in (None, '', [], {}):
            return
        print(f'{name}: {value}')

    field('GHSA', a.get('ghsa_id'))
    field('CVE', a.get('cve_id'))
    severity = (a.get('severity') or '').lower()
    field('Severity', severity or None)
    field('State', a.get('state'))
    field('Created', a.get('created_at'))
    field('Published', a.get('published_at'))
    field('Updated', a.get('updated_at'))
    field('URL', a.get('html_url'))

    cvss = a.get('cvss') or {}
    if cvss.get('score') is not None:
        vector = cvss.get('vector_string') or ''
        print(f'CVSS: {cvss.get("score")} {vector}'.rstrip())

    cwes = [c.get('cwe_id') for c in (a.get('cwes') or []) if c.get('cwe_id')]
    if cwes:
        print(f'CWEs: {", ".join(cwes)}')

    if a.get('summary'):
        print()
        print(f'Summary: {a["summary"]}')

    if a.get('description'):
        print()
        print('Description:')
        print(a['description'])

    patches = parse_patches(a.get('description'))
    if patches:
        print(f'\nPatches:\n{patches}')

    vulns = a.get('vulnerabilities') or []
    if vulns:
        print()
        print('Affected packages:')
        for v in vulns:
            pkg = v.get('package') or {}
            name = pkg.get('name') or '-'
            ecosystem = pkg.get('ecosystem') or '-'
            vulnerable = v.get('vulnerable_version_range') or '-'
            patched = v.get('patched_versions') or '-'
            print(f'  - {ecosystem}:{name}')
            print(f'      vulnerable: {vulnerable}')
            print(f'      patched:    {patched}')

    refs = a.get('references') or []
    if refs:
        print()
        print('References:')
        for ref in refs:
            url = ref.get('url') if isinstance(ref, dict) else ref
            if url:
                print(f'  - {url}')


def print_table(advisories: list[dict[str, Any]]) -> None:
    if not advisories:
        print('No advisories found.')
        return
    fmt = '{:<20} {:<16} {:<10} {:<12} {:<8} {:<12} {}'
    print(fmt.format('GHSA', 'CVE', 'Severity', 'State', 'Patches',
                     'Embargo', 'Summary'))
    print('-' * 120)
    for a in advisories:
        ghsa = a.get('ghsa_id', '') or ''
        cve = a.get('cve_id') or '-'
        severity = (a.get('severity') or '-').lower()
        state = a.get('state', '-') or '-'
        patches = 'yes' if parse_patches(a.get('description')) else 'no'
        embargo = get_embargo(a.get("created_at"))
        summary = (a.get('summary') or '').replace('\n', ' ')
        if len(summary) > 50:
            summary = summary[:47] + '...'
        print(fmt.format(ghsa, cve, severity, state, patches,
                         embargo, summary))


CREATE_TABLE = '''
CREATE TABLE IF NOT EXISTS advisories (
    ghsa_id      TEXT PRIMARY KEY,
    cve_id       TEXT,
    summary      TEXT,
    severity     TEXT,
    state        TEXT,
    cvss_score   REAL,
    cvss_vector  TEXT,
    cwes         TEXT,
    html_url     TEXT,
    created_at   TEXT,
    published_at TEXT,
    updated_at   TEXT,
    embargo      TEXT,
    raw          TEXT NOT NULL,
    synced_at    TEXT NOT NULL
)
'''

UPSERT = '''
INSERT INTO advisories (
    ghsa_id, cve_id, summary, severity, state, cvss_score, cvss_vector,
    cwes, html_url, created_at, published_at, updated_at, embargo,
    raw, synced_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ghsa_id) DO UPDATE SET
    cve_id       = excluded.cve_id,
    summary      = excluded.summary,
    severity     = excluded.severity,
    state        = excluded.state,
    cvss_score   = excluded.cvss_score,
    cvss_vector  = excluded.cvss_vector,
    cwes         = excluded.cwes,
    html_url     = excluded.html_url,
    created_at   = excluded.created_at,
    published_at = excluded.published_at,
    updated_at   = excluded.updated_at,
    embargo      = excluded.embargo,
    raw          = excluded.raw,
    synced_at    = excluded.synced_at
'''


def advisory_row(a: dict[str, Any], synced_at: str) -> tuple[Any, ...]:
    cvss = a.get('cvss') or {}
    cwes = [c.get('cwe_id') for c in (a.get('cwes') or []) if c.get('cwe_id')]
    created_at = a.get('created_at')
    return (
        a.get('ghsa_id'),
        a.get('cve_id'),
        a.get('summary'),
        (a.get('severity') or '').lower() or None,
        a.get('state'),
        cvss.get('score'),
        cvss.get('vector_string'),
        json.dumps(cwes) if cwes else None,
        a.get('html_url'),
        created_at,
        a.get('published_at'),
        a.get('updated_at'),
        get_embargo(created_at) if created_at else None,
        json.dumps(a, sort_keys=True),
        synced_at,
    )


def sync_to_db(db_path: str,
               advisories: list[dict[str, Any]]) -> int:
    '''Upsert advisories into a local libSQL/Turso database.

    When TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are set, the local file
    is opened as an embedded replica and changes are pushed to the
    remote Turso database.
    '''
    try:
        import libsql
    except ImportError:
        sys.exit('error: the "libsql" package is required for --sync-db '
                 '(install it, e.g. `uv add libsql`)')

    sync_url = os.environ.get('TURSO_DATABASE_URL')
    auth_token = os.environ.get('TURSO_AUTH_TOKEN')
    if sync_url:
        conn = libsql.connect(db_path, sync_url=sync_url,
                              auth_token=auth_token)
        conn.sync()
    else:
        conn = libsql.connect(db_path)

    conn.execute(CREATE_TABLE)
    synced_at = datetime.now().astimezone().isoformat()
    count = 0
    for a in advisories:
        if not a.get('ghsa_id'):
            continue
        conn.execute(UPSERT, advisory_row(a, synced_at))
        count += 1
    conn.commit()
    if sync_url:
        conn.sync()
    return count


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repo', default=DEFAULT_REPO,
                        help=f'owner/name repo slug (default: {DEFAULT_REPO})')
    parser.add_argument('--state', action='append',
                        choices=['triage', 'draft', 'published', 'closed'],
                        help='repo advisories: state to fetch; may be given '
                             'multiple times (default: draft and triage)')
    parser.add_argument('--severity',
                        choices=['low', 'medium', 'high', 'critical'],
                        help='filter by severity')
    parser.add_argument('--ghsa',
                        help='fetch a single advisory by GHSA id')
    parser.add_argument('--sync-db', metavar='PATH',
                        help='sync every advisory (all states) into the '
                             'local libSQL/Turso database at PATH (set '
                             'TURSO_DATABASE_URL and TURSO_AUTH_TOKEN to '
                             'also push to a remote Turso database)')
    parser.add_argument('--past-embargo', action='store_true',
                        help='only show advisories whose 90-day embargo '
                             'period has already elapsed')
    parser.add_argument('--json', action='store_true',
                        help='emit raw JSON instead of a summary table')
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'zephyr-fetch-advisories',
    })
    token = get_token()
    if token:
        session.headers['Authorization'] = f'Bearer {token}'
    else:
        sys.exit('error: a GitHub token is required for repository '
                 'advisories (set GITHUB_TOKEN or configure ~/.netrc)')

    if args.ghsa:
        advisory = fetch_advisory(session, args.ghsa, args.repo)
        if args.json:
            json.dump(advisory, sys.stdout, indent=2)
            sys.stdout.write('\n')
        else:
            print_advisory(advisory)
        return 0

    if args.sync_db:
        advisories = fetch_repo_advisories(session, args.repo,
                                           list(ALL_STATES))
        count = sync_to_db(args.sync_db, advisories)
        print(f'Synced {count} advisories to {args.sync_db}')
        return 0

    states = args.state if args.state else list(DEFAULT_STATES)
    advisories = fetch_repo_advisories(session, args.repo, states)
    if args.severity:
        advisories = filter_severity(advisories, args.severity)

    if args.past_embargo:
        advisories = filter_past_embargo(advisories)

    if args.json:
        json.dump(advisories, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        print_table(advisories)
    return 0


if __name__ == '__main__':
    sys.exit(main())
