#!/usr/bin/env python3
# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''Update a GHSA advisory's collaborators on GitHub from a JSON file.

The JSON file is the collaborators payload produced by the
``/ghsa-collaborators`` workflow, e.g.::

    {
      "collaborating_teams": ["security"],
      "collaborating_users": ["ceolin"]
    }

Usage::

    python3 scripts/update_collaborators.py GHSA-xxxx-xxxx-xxxx collaborators.json
'''

import argparse
import json
import os
import sys

# Ensure the scripts/ directory is on sys.path so `import ghsa` resolves.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghsa import github as gh_mod  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('ghsa_id', help='advisory id, e.g. GHSA-xxxx-xxxx-xxxx')
    parser.add_argument('json_file', help='collaborators JSON payload')
    parser.add_argument('--repo', default=gh_mod.DEFAULT_REPO,
                        help=f'owner/name repo slug (default: {gh_mod.DEFAULT_REPO})')
    parser.add_argument('--dry-run', action='store_true',
                        help='print the payload without changing GitHub')
    args = parser.parse_args()

    try:
        with open(args.json_file, 'r', encoding='utf-8') as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f'error: cannot read JSON file: {exc}')

    # Only forward the collaborator fields accepted by the update endpoint.
    payload = {k: payload[k] for k in
               ('collaborating_teams', 'collaborating_users')
               if k in payload}
    if not payload:
        sys.exit('error: JSON file has no collaborating_teams/'
                 'collaborating_users fields')

    if args.dry_run:
        print(f'Would PATCH {args.ghsa_id} in {args.repo} with:')
        print(json.dumps(payload, indent=2))
        return

    gh_mod.patch_advisory(args.ghsa_id, payload, args.repo)

    added = ', '.join(payload.get('collaborating_teams', [])
                      + payload.get('collaborating_users', []))
    print(f'{args.ghsa_id}: collaborators updated ({added})')


if __name__ == '__main__':
    main()
