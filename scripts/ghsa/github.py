# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''GitHub API helpers: authentication, pagination, advisory fetch and create.'''

import netrc
import os
import sys
from typing import Any, Iterator, Optional

import requests

GITHUB_API = 'https://api.github.com'
DEFAULT_REPO = 'zephyrproject-rtos/zephyr'


# ─── Authentication ───────────────────────────────────────────────────────────

def get_token() -> Optional[str]:
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        return token
    try:
        nrc = netrc.netrc()
    except (FileNotFoundError, netrc.NetrcParseError):
        return None
    auth = nrc.authenticators('github.com')
    return auth[2] if auth else None


def github_session() -> requests.Session:
    token = get_token()
    if not token:
        sys.exit('error: a GitHub token is required '
                 '(set GITHUB_TOKEN or configure ~/.netrc)')
    session = requests.Session()
    session.headers.update({
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'swg-tools/ghsa',
    })
    return session


# ─── Pagination ───────────────────────────────────────────────────────────────

def paginate(session: requests.Session, url: str,
             params: dict[str, Any]) -> Iterator[dict[str, Any]]:
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
        params = {}


# ─── Advisory endpoints ───────────────────────────────────────────────────────

def fetch_advisories(session: requests.Session, repo: str,
                     states: list[str]) -> list[dict[str, Any]]:
    '''Fetch advisories for every requested state and return them combined.'''
    url = f'{GITHUB_API}/repos/{repo}/security-advisories'
    result: list[dict[str, Any]] = []
    for state in states:
        result.extend(paginate(session, url, {'state': state}))
    return result


def _check_advisory_response(resp: requests.Response) -> None:
    if resp.status_code == 403:
        sys.exit('error: GitHub permission denied; ensure your token has '
                 'the `repo` scope and write access to security advisories')
    if resp.status_code == 422:
        sys.exit(f'error: GitHub rejected the payload: {resp.json()}')
    resp.raise_for_status()


def post_advisory(payload: dict[str, Any], repo: str,
                  session: Optional[requests.Session] = None) -> dict[str, Any]:
    '''Create a draft security advisory and return the GitHub response.'''
    session = session or github_session()
    url = f'{GITHUB_API}/repos/{repo}/security-advisories'
    resp = session.post(url, json=payload, timeout=30)
    _check_advisory_response(resp)
    return resp.json()


def patch_advisory(ghsa_id: str, payload: dict[str, Any], repo: str,
                   session: Optional[requests.Session] = None) -> dict[str, Any]:
    '''Update an existing security advisory and return the GitHub response.

    Some fields (notably ``collaborating_teams`` and ``collaborating_users``)
    are only accepted by the update endpoint, not by create.
    '''
    session = session or github_session()
    url = f'{GITHUB_API}/repos/{repo}/security-advisories/{ghsa_id}'
    resp = session.patch(url, json=payload, timeout=30)
    _check_advisory_response(resp)
    return resp.json()
