#!/usr/bin/env python3
# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

'''
Fetch security advisories from GitHub using the REST API.

By default, this lists repository security advisories for
zephyrproject-rtos/zephyr. Use --global to query GitHub's global
advisory database instead.

Authentication:
    A GitHub token is required for repository advisories and strongly
    recommended otherwise (to avoid rate limiting). The token is read
    from the GITHUB_TOKEN environment variable, or ~/.netrc for
    github.com.

Examples:
    # Draft + triage advisories for zephyrproject-rtos/zephyr (default)
    ./fetch_advisories.py

    # Only published advisories, JSON output
    ./fetch_advisories.py --state published --json

    # Fetch multiple explicit states
    ./fetch_advisories.py --state triage --state published

    # Global advisories affecting a given ecosystem / package
    ./fetch_advisories.py --global --ecosystem pip --severity high

    # Fetch a single advisory by GHSA id (repo by default; --global for DB)
    ./fetch_advisories.py --ghsa GHSA-xxxx-xxxx-xxxx
    ./fetch_advisories.py --global --ghsa GHSA-xxxx-xxxx-xxxx
'''

import argparse
import json
import netrc
import os
import sys
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


def fetch_repo_advisories(session: requests.Session, repo: str,
                          states: list[str]) -> list[dict[str, Any]]:
    # The GitHub API accepts only one state per call, so fetch each
    # requested state separately and concatenate.
    url = f'{GITHUB_API}/repos/{repo}/security-advisories'
    result: list[dict[str, Any]] = []
    for state in states:
        result.extend(paginate(session, url, {'state': state}))
    return result


def fetch_global_advisories(session: requests.Session,
                            ecosystem: Optional[str],
                            severity: Optional[str],
                            cve: Optional[str]) -> list[dict[str, Any]]:
    url = f'{GITHUB_API}/advisories'
    params: dict[str, Any] = {}
    if ecosystem:
        params['ecosystem'] = ecosystem
    if severity:
        params['severity'] = severity
    if cve:
        params['cve_id'] = cve
    return list(paginate(session, url, params))


def fetch_advisory(session: requests.Session, ghsa: str,
                   repo: Optional[str]) -> dict[str, Any]:
    if repo:
        url = f'{GITHUB_API}/repos/{repo}/security-advisories/{ghsa}'
    else:
        url = f'{GITHUB_API}/advisories/{ghsa}'
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
    fmt = '{:<20} {:<16} {:<10} {:<12} {}'
    print(fmt.format('GHSA', 'CVE', 'Severity', 'State', 'Summary'))
    print('-' * 100)
    for a in advisories:
        ghsa = a.get('ghsa_id', '') or ''
        cve = a.get('cve_id') or '-'
        severity = (a.get('severity') or '-').lower()
        state = a.get('state', '-') or '-'
        summary = (a.get('summary') or '').replace('\n', ' ')
        if len(summary) > 60:
            summary = summary[:57] + '...'
        print(fmt.format(ghsa, cve, severity, state, summary))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repo', default=DEFAULT_REPO,
                        help=f'owner/name repo slug (default: {DEFAULT_REPO})')
    parser.add_argument('--global', dest='global_db', action='store_true',
                        help='query the global GitHub Advisory Database '
                             'instead of a repository')
    parser.add_argument('--state', action='append',
                        choices=['triage', 'draft', 'published', 'closed'],
                        help='repo advisories: state to fetch; may be given '
                             'multiple times (default: draft and triage)')
    parser.add_argument('--severity',
                        choices=['low', 'medium', 'high', 'critical'],
                        help='filter by severity')
    parser.add_argument('--ecosystem',
                        help='global advisories: filter by ecosystem '
                             '(e.g. pip, npm, maven)')
    parser.add_argument('--cve', help='global advisories: filter by CVE id')
    parser.add_argument('--ghsa',
                        help='fetch a single advisory by GHSA id (uses the '
                             'repo endpoint unless --global is given)')
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
    elif not args.global_db:
        sys.exit('error: a GitHub token is required for repository '
                 'advisories (set GITHUB_TOKEN or configure ~/.netrc)')

    if args.ghsa:
        repo = None if args.global_db else args.repo
        advisory = fetch_advisory(session, args.ghsa, repo)
        if args.json:
            json.dump(advisory, sys.stdout, indent=2)
            sys.stdout.write('\n')
        else:
            print_advisory(advisory)
        return 0

    if args.global_db:
        advisories = fetch_global_advisories(
            session, args.ecosystem, args.severity, args.cve)
    else:
        states = args.state if args.state else list(DEFAULT_STATES)
        advisories = fetch_repo_advisories(session, args.repo, states)
        if args.severity:
            advisories = filter_severity(advisories, args.severity)

    if args.json:
        json.dump(advisories, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        print_table(advisories)
    return 0


if __name__ == '__main__':
    sys.exit(main())
