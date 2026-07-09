# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''AI-assisted advisory generation via OpenRouter.'''

import json
import os
import re
import sys
from typing import Any, Optional

from .maintainers import SECURITY_TEAM

OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions'
DEFAULT_MODEL = 'deepseek/deepseek-v4-flash'

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

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


def _load(filename: str) -> str:
    with open(os.path.join(_PACKAGE_DIR, filename), 'r', encoding='utf-8') as fh:
        return fh.read()


ADVISORY_TEMPLATE = _load('ghsa_template.md')
SYSTEM_PROMPT = _load('ghsa_prompt.md') + ADVISORY_TEMPLATE


# ─── Input ────────────────────────────────────────────────────────────────────

def read_email(source: str) -> str:
    if source == '-':
        return sys.stdin.read()
    try:
        with open(source, 'r', encoding='utf-8', errors='replace') as fh:
            return fh.read()
    except OSError as exc:
        sys.exit(f'error: cannot read email file: {exc}')


# ─── OpenRouter call ──────────────────────────────────────────────────────────

def call_openrouter(email_content: str, model: str) -> str:
    import requests

    key = os.environ.get('OPENROUTER_API_KEY')
    if not key:
        sys.exit('error: OPENROUTER_API_KEY environment variable is not set')

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
            'Authorization': f'Bearer {key}',
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://github.com/zephyrproject-rtos/zephyr',
            'X-Title': 'swg-tools/ghsa',
        },
        json=payload,
        timeout=120,
    )
    if resp.status_code == 401:
        sys.exit('error: OpenRouter authentication failed; check OPENROUTER_API_KEY')
    if resp.status_code == 429:
        sys.exit('error: OpenRouter rate limit exceeded')
    resp.raise_for_status()
    choices = resp.json().get('choices') or []
    if not choices:
        sys.exit('error: empty response from OpenRouter')
    return choices[0]['message']['content']


# ─── Parsing ──────────────────────────────────────────────────────────────────

def split_advisory_and_metadata(
        raw: str) -> tuple[str, Optional[dict[str, Any]]]:
    '''Split the model response into the markdown body and the JSON metadata block.'''
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


# ─── Building ─────────────────────────────────────────────────────────────────

def build_full_advisory(body: str, embargo: str) -> str:
    parts = [body, '', PATCHES_SECTION, '', FOR_MORE_INFO_SECTION,
             '', f'embargo: {embargo}', '']
    return '\n'.join(parts)


def build_github_json(
    metadata: Optional[dict[str, Any]],
    description: str,
    collaborators: Optional[list[str]] = None,
) -> dict[str, Any]:
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
        'package': {'ecosystem': 'other', 'name': 'zephyr'},
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
             'url': (f'https://github.com/zephyrproject-rtos/zephyr'
                     f'/commit/{fix_commit}')}
        ]
    return payload


def make_slug(metadata: Optional[dict[str, Any]]) -> str:
    if metadata:
        summary = metadata.get('summary', '')
        if summary:
            slug = re.sub(r'[^a-z0-9]+', '-', summary.lower()).strip('-')
            return slug[:60] or 'advisory'
    return 'advisory'


# ─── Output ───────────────────────────────────────────────────────────────────

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
