# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''Lookup Zephyr maintainers for affected source files via get_maintainer.py.'''

import os
import re
import subprocess
import sys

SECURITY_TEAM = 'security'

_MAINTAINER_LINE_RE = re.compile(
    r'^\s+(?:maintainers|collaborators):\s*(.+)$', re.MULTILINE)


def get_file_maintainers(file_path: str, zephyr_base: str) -> list[str]:
    '''Return GitHub handles listed as maintainers or collaborators for a file.'''
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
    for m in _MAINTAINER_LINE_RE.finditer(result.stdout):
        for handle in m.group(1).split(','):
            handle = handle.strip()
            if handle:
                handles.append(handle)
    return handles


def collect_collaborators(affected_files: list[str]) -> list[str]:
    '''Return a deduplicated list of maintainer handles for all affected files.'''
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
