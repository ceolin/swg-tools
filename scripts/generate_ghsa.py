#!/usr/bin/env python3
# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

'''
Generate a GHSA advisory document from a vulnerability report email.

Reads an email describing a security vulnerability (from a file or stdin),
sends it to OpenRouter.ai to produce a structured advisory in the project's
standard format, appends mandatory boilerplate (Patches table, contact info,
embargo date), and writes both a Markdown advisory and a GitHub API JSON
payload.

Can also create the advisory directly on GitHub from a previously generated
JSON file.

Authentication:
    OPENROUTER_API_KEY environment variable must be set for --email.
    GITHUB_TOKEN or ~/.netrc must be configured for --create.

Examples:
    # Generate from a file
    ./generate_ghsa.py --email report.eml

    # Pipe email from stdin
    cat report.eml | ./generate_ghsa.py --email -

    # Custom output directory and model
    ./generate_ghsa.py --email report.eml --output ./advisories --model openai/gpt-4o

    # Print advisory to stdout instead of writing files
    ./generate_ghsa.py --email report.eml --stdout

    # Create a draft advisory on GitHub from the generated JSON
    ./generate_ghsa.py --create ./advisories/my-advisory-github.json
'''

import argparse
import json
import netrc
import os
import re
import subprocess
import sys
from datetime import date
from typing import Any, Optional


OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions'
DEFAULT_MODEL = "deepseek/deepseek-v4-flash"
DEFAULT_REPO = 'zephyrproject-rtos/zephyr'

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


def _load(filename: str) -> str:
    path = os.path.join(_SCRIPTS_DIR, filename)
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


ADVISORY_TEMPLATE = _load('ghsa_template.md')
SYSTEM_PROMPT = _load('ghsa_prompt.md') + ADVISORY_TEMPLATE


PATCHES_SECTION = '''\
<!-- zepsec:patch -->
### Patches

| Branch | Pull request | Status |
| --- | --- | --- |
<!-- zepsec:patch -->'''

FOR_MORE_INFO_SECTION = '''\
### For more information

If you have any questions or comments about this advisory:
* Open an issue in [zephyr](https://github.com/zephyrproject-rtos/zephyr/issues/)
* Email us at [Zephyr-vulnerabilities](mailto:vulnerabilities@lists.zephyrproject.org)'''


def get_api_key() -> str:
    key = os.environ.get('OPENROUTER_API_KEY')
    if not key:
        sys.exit('error: OPENROUTER_API_KEY environment variable is not set')
    return key


def read_email(source: str) -> str:
    if source == '-':
        return sys.stdin.read()
    try:
        with open(source, 'r', encoding='utf-8', errors='replace') as fh:
            return fh.read()
    except OSError as exc:
        sys.exit(f'error: cannot read email file: {exc}')


def call_openrouter(email_content: str, model: str) -> str:
    try:
        import requests
    except ImportError:
        sys.exit('error: the "requests" package is required')

    api_key = get_api_key()

    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': (
                'Here is the vulnerability report email.  Generate the advisory'
                ' document following the template and rules above.\n\n'
                + email_content
            )},
        ],
    }

    resp = requests.post(
        OPENROUTER_API_URL,
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://github.com/zephyrproject-rtos/zephyr',
            'X-Title': 'swg-tools/generate-ghsa',
        },
        json=payload,
        timeout=120,
    )

    if resp.status_code == 401:
        sys.exit('error: OpenRouter authentication failed; check OPENROUTER_API_KEY')
    if resp.status_code == 429:
        sys.exit('error: OpenRouter rate limit exceeded')
    resp.raise_for_status()

    data = resp.json()
    choices = data.get('choices') or []
    if not choices:
        sys.exit(f'error: empty response from OpenRouter: {data}')
    return choices[0]['message']['content']


def split_advisory_and_metadata(raw: str) -> tuple[str, Optional[dict[str, Any]]]:
    '''Separate the markdown body from the trailing JSON metadata block.'''
    # Find the last ```json … ``` fence
    json_fence_re = re.compile(r'```json\s*(.*?)\s*```', re.DOTALL)
    matches = list(json_fence_re.finditer(raw))
    if not matches:
        return raw.strip(), None

    last = matches[-1]
    advisory_body = raw[:last.start()].rstrip()
    try:
        metadata = json.loads(last.group(1))
    except json.JSONDecodeError as exc:
        print(f'warning: could not parse metadata JSON: {exc}', file=sys.stderr)
        metadata = None

    return advisory_body, metadata


def build_full_advisory(body: str, embargo: str) -> str:
    '''Append the mandatory boilerplate sections to the advisory body.'''
    parts = [
        body,
        '',
        PATCHES_SECTION,
        '',
        FOR_MORE_INFO_SECTION,
        '',
        f'embargo: {embargo}',
        '',
    ]
    return '\n'.join(parts)


def build_github_json(metadata: Optional[dict[str, Any]],
                      description: str,
                      collaborators: Optional[list[str]] = None) -> dict[str, Any]:
    '''Build the payload for the GitHub Repos Security Advisories API.'''
    if metadata is None:
        metadata = {}

    version_from = metadata.get('affected_versions_from')
    version_to = metadata.get('affected_versions_to')
    patched = metadata.get('patched_versions')

    if version_from and version_to:
        version_range = f'>= {version_from}, <= {version_to}'
    elif version_to:
        version_range = f'<= {version_to}'
    elif version_from:
        version_range = f'>= {version_from}'
    else:
        version_range = None

    vulnerability: dict[str, Any] = {
        'package': {
            'ecosystem': 'other',
            'name': 'zephyr',
        },
    }
    if version_range:
        vulnerability['vulnerable_version_range'] = version_range
    if patched:
        vulnerability['patched_versions'] = patched

    payload: dict[str, Any] = {
        'summary': metadata.get('summary', ''),
        'description': description,
        'severity': metadata.get('severity', 'medium'),
        'vulnerabilities': [vulnerability],
        'collaborating_teams': [SECURITY_TEAM],
    }

    if collaborators:
        payload['collaborating_users'] = collaborators

    cwes = metadata.get('cwes') or []
    if cwes:
        payload['cwe_ids'] = cwes

    fix_commit = metadata.get('fix_commit')
    if fix_commit:
        payload['references'] = [
            {'type': 'FIX',
             'url': f'https://github.com/zephyrproject-rtos/zephyr/commit/{fix_commit}'}
        ]

    return payload


def write_output(advisory: str, github_json: dict[str, Any],
                 output_dir: str, slug: str) -> tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    advisory_path = os.path.join(output_dir, f'{slug}.md')
    json_path = os.path.join(output_dir, f'{slug}-github.json')

    with open(advisory_path, 'w', encoding='utf-8') as fh:
        fh.write(advisory)
        if not advisory.endswith('\n'):
            fh.write('\n')

    with open(json_path, 'w', encoding='utf-8') as fh:
        json.dump(github_json, fh, indent=2, sort_keys=True)
        fh.write('\n')

    return advisory_path, json_path


MAINTAINER_LINE_RE = re.compile(
    r'^\s+(?:maintainers|collaborators):\s*(.+)$', re.MULTILINE)

SECURITY_TEAM = 'security'


def get_file_maintainers(file_path: str, zephyr_base: str) -> list[str]:
    '''Return GitHub handles of maintainers/collaborators for a source file.'''
    script = os.path.join(zephyr_base, 'scripts', 'get_maintainer.py')
    try:
        result = subprocess.run(
            [sys.executable, script, 'path', file_path],
            capture_output=True, text=True, cwd=zephyr_base, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f'warning: get_maintainer.py failed for {file_path}: {exc}',
              file=sys.stderr)
        return []

    handles: list[str] = []
    for m in MAINTAINER_LINE_RE.finditer(result.stdout):
        for handle in m.group(1).split(','):
            handle = handle.strip()
            if handle:
                handles.append(handle)
    return handles


def collect_collaborators(affected_files: list[str]) -> list[str]:
    '''Gather unique maintainer handles for all affected files.'''
    zephyr_base = os.environ.get('ZEPHYR_BASE', '')
    if not zephyr_base:
        print('warning: ZEPHYR_BASE is not set; skipping maintainer lookup',
              file=sys.stderr)
        return []

    seen: set[str] = set()
    result: list[str] = []
    for path in affected_files:
        for handle in get_file_maintainers(path, zephyr_base):
            if handle not in seen:
                seen.add(handle)
                result.append(handle)
    return result


def get_github_token() -> Optional[str]:
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        return token
    try:
        nrc = netrc.netrc()
    except (FileNotFoundError, netrc.NetrcParseError):
        return None
    auth = nrc.authenticators('github.com')
    return auth[2] if auth else None


GITHUB_API = 'https://api.github.com'


def create_github_advisory(json_path: str, repo: str) -> None:
    '''Read a GitHub API JSON file and create a draft security advisory.'''
    try:
        import requests
    except ImportError:
        sys.exit('error: the "requests" package is required')

    token = get_github_token()
    if not token:
        sys.exit('error: a GitHub token is required to create advisories '
                 '(set GITHUB_TOKEN or configure ~/.netrc)')

    try:
        with open(json_path, 'r', encoding='utf-8') as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f'error: cannot read JSON file: {exc}')

    url = f'{GITHUB_API}/repos/{repo}/security-advisories'
    resp = requests.post(
        url,
        headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {token}',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'swg-tools/generate-ghsa',
        },
        json=payload,
        timeout=30,
    )

    if resp.status_code == 401:
        sys.exit('error: GitHub authentication failed; check GITHUB_TOKEN or ~/.netrc')
    if resp.status_code == 403:
        sys.exit('error: GitHub permission denied; ensure your token has '
                 'the `repo` scope and write access to security advisories')
    if resp.status_code == 422:
        sys.exit(f'error: GitHub rejected the payload: {resp.json()}')
    resp.raise_for_status()

    advisory = resp.json()
    ghsa_id = advisory.get('ghsa_id', '(unknown)')
    html_url = advisory.get('html_url', '')
    print(f'Created : {ghsa_id}')
    if html_url:
        print(f'URL     : {html_url}')


def make_slug(metadata: Optional[dict[str, Any]]) -> str:
    if metadata:
        summary = metadata.get('summary', '')
        if summary:
            slug = re.sub(r'[^a-z0-9]+', '-', summary.lower()).strip('-')
            return slug[:60] or 'advisory'
    return 'advisory'


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '--email', metavar='FILE',
        help='path to the email file, or - to read from stdin')
    parser.add_argument(
        '--create', metavar='JSON_FILE',
        help='create a draft advisory on GitHub from the given JSON file '
             '(produced by a previous run); does not require --email')
    parser.add_argument(
        '--repo', default=DEFAULT_REPO,
        help=f'owner/name repo slug for --create (default: {DEFAULT_REPO})')
    parser.add_argument(
        '--output', default='./advisories', metavar='DIR',
        help='directory for output files (default: ./advisories)')
    parser.add_argument(
        '--model', default=DEFAULT_MODEL,
        help=f'OpenRouter model to use (default: {DEFAULT_MODEL})')
    parser.add_argument(
        '--embargo', metavar='DATE',
        help='embargo date as YYYY-MM-DD (default: today)')
    parser.add_argument(
        '--stdout', action='store_true',
        help='print the advisory to stdout instead of writing files')
    args = parser.parse_args()

    if args.create:
        create_github_advisory(args.create, args.repo)
        return 0

    if not args.email:
        parser.error('one of --email or --create is required')

    embargo = args.embargo or date.today().isoformat()

    print('Reading email…', file=sys.stderr)
    email_content = read_email(args.email)

    print(f'Calling OpenRouter ({args.model})…', file=sys.stderr)
    raw_response = call_openrouter(email_content, args.model)

    advisory_body, metadata = split_advisory_and_metadata(raw_response)
    full_advisory = build_full_advisory(advisory_body, embargo)

    affected_files = (metadata or {}).get('affected_files') or []
    if affected_files:
        print('Looking up maintainers…', file=sys.stderr)
    collaborators = collect_collaborators(affected_files)
    if collaborators:
        print(f'Collaborators: {", ".join(collaborators)}', file=sys.stderr)

    github_json = build_github_json(metadata, full_advisory, collaborators)

    if args.stdout:
        print(full_advisory)
        print('\n--- GitHub API JSON ---', file=sys.stderr)
        json.dump(github_json, sys.stderr, indent=2)
        print(file=sys.stderr)
        return 0

    slug = make_slug(metadata)
    advisory_path, json_path = write_output(
        full_advisory, github_json, args.output, slug)

    print(f'Advisory : {advisory_path}', file=sys.stderr)
    print(f'GitHub JSON: {json_path}', file=sys.stderr)
    if metadata:
        print(f'Summary    : {metadata.get("summary", "(none)")}', file=sys.stderr)
        print(f'Severity   : {metadata.get("severity", "(none)")}', file=sys.stderr)
        print(f'Embargo    : {embargo}', file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
