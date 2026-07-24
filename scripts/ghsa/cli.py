# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''Click CLI — all commands and display helpers for the ghsa tool.'''

import json
import os
import sys
import webbrowser
from datetime import date, datetime, timedelta
from typing import Any, Optional

import click

from . import dashboard as dash_mod
from . import db as db_mod
from . import generate as gen_mod
from . import github as gh_mod
from . import maintainers as maint_mod

_DEFAULT_DB = 'advisories.db'


# ─── Root group ───────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    '''Zephyr RTOS security advisory tool.

    Manage, generate, and publish GitHub Security Advisories (GHSA)
    for the zephyrproject-rtos/zephyr repository.

    \b
    Typical workflow:
      ghsa sync                    # populate local DB from GitHub
      ghsa list                    # browse draft/triage advisories
      ghsa show GHSA-xxxx-xxxx-xxxx
      ghsa generate --email report.eml
      ghsa create advisory-github.json
      ghsa dashboard --open
    '''


# ─── Display helpers ──────────────────────────────────────────────────────────

def _print_advisory(a: dict[str, Any]) -> None:
    def field(name: str, value: Any) -> None:
        if value not in (None, '', [], {}):
            click.echo(f'{name}: {value}')

    field('GHSA', a.get('ghsa_id'))
    field('CVE', a.get('cve_id'))
    field('Severity', (a.get('severity') or '').lower() or None)
    field('State', a.get('state'))
    field('Created', a.get('created_at'))
    field('Published', a.get('published_at'))
    field('Updated', a.get('updated_at'))
    field('URL', a.get('html_url'))

    cvss = a.get('cvss') or {}
    if cvss.get('score') is not None:
        vector = cvss.get('vector_string') or ''
        click.echo(f'CVSS: {cvss["score"]} {vector}'.rstrip())

    cwes = [c.get('cwe_id') for c in (a.get('cwes') or []) if c.get('cwe_id')]
    if cwes:
        click.echo(f'CWEs: {", ".join(cwes)}')

    if a.get('summary'):
        click.echo(f'\nSummary: {a["summary"]}')

    if a.get('description'):
        click.echo('\nDescription:')
        click.echo(a['description'])

    patches = db_mod.parse_patches(a.get('description'))
    if patches:
        click.echo(f'\nPatches:\n{patches}')

    vulns = a.get('vulnerabilities') or []
    if vulns:
        click.echo('\nAffected packages:')
        for v in vulns:
            pkg = v.get('package') or {}
            click.echo(f'  - {pkg.get("ecosystem", "-")}:{pkg.get("name", "-")}')
            click.echo(f'      vulnerable: {v.get("vulnerable_version_range") or "-"}')
            click.echo(f'      patched:    {v.get("patched_versions") or "-"}')

    refs = a.get('references') or []
    if refs:
        click.echo('\nReferences:')
        for ref in refs:
            url = ref.get('url') if isinstance(ref, dict) else ref
            if url:
                click.echo(f'  - {url}')


def _print_table(advisories: list[dict[str, Any]]) -> None:
    if not advisories:
        click.echo('No advisories found.')
        return
    fmt = '{:<20} {:<16} {:<10} {:<12} {:<8} {:<12} {}'
    click.echo(fmt.format('GHSA', 'CVE', 'Severity', 'State',
                          'Patches', 'Embargo', 'Summary'))
    click.echo('-' * 120)
    for a in advisories:
        summary = (a.get('summary') or '').replace('\n', ' ')
        if len(summary) > 50:
            summary = summary[:47] + '...'
        click.echo(fmt.format(
            a.get('ghsa_id', '') or '',
            a.get('cve_id') or '-',
            (a.get('severity') or '-').lower(),
            a.get('state', '-') or '-',
            'yes' if db_mod.parse_patches(a.get('description')) else 'no',
            db_mod.get_embargo(a.get('created_at')),
            summary,
        ))


# ─── Guard helpers ────────────────────────────────────────────────────────────

def _require_db(db_path: str) -> None:
    sync_url, _ = db_mod.turso_credentials()
    if not sync_url and not os.path.exists(db_path):
        raise click.ClickException(
            f'no advisory database at {db_path}; run `ghsa sync` first')


def _require_table(conn: Any, db_path: str) -> None:
    if not db_mod.has_advisories_table(conn):
        raise click.ClickException(
            f'no advisories in {db_path}; run `ghsa sync` first')


# ─── Commands ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option('--db', default=_DEFAULT_DB, metavar='PATH', show_default=True,
              help='local libSQL/Turso database file')
@click.option('--repo', default=gh_mod.DEFAULT_REPO, show_default=True,
              help='GitHub owner/name repo slug')
def sync(db: str, repo: str) -> None:
    '''Sync all advisories from GitHub into the local database.'''
    session = gh_mod.github_session()
    advisories = gh_mod.fetch_advisories(session, repo, list(db_mod.ALL_STATES))
    count = db_mod.sync_to_db(db, repo, advisories)
    click.echo(f'Synced {count} advisories from {repo} to {db}')


@cli.command('list')
@click.option('--db', default=_DEFAULT_DB, metavar='PATH', show_default=True,
              help='local database file')
@click.option('--repo', default=gh_mod.DEFAULT_REPO, show_default=True,
              help='filter by repo slug')
@click.option('--state', 'states', multiple=True,
              type=click.Choice(db_mod.ALL_STATES),
              help='filter by state; repeatable (default: draft + triage)')
@click.option('--severity',
              type=click.Choice(['low', 'medium', 'high', 'critical']),
              help='filter by severity')
@click.option('--past-embargo', is_flag=True,
              help='only show advisories whose 90-day embargo has elapsed')
@click.option('--synced', is_flag=True,
              help='only show advisories synced at or after the global marker')
@click.option('--json', 'as_json', is_flag=True,
              help='emit raw JSON instead of a summary table')
def list_cmd(db: str, repo: str, states: tuple[str, ...],
             severity: Optional[str], past_embargo: bool,
             synced: bool, as_json: bool) -> None:
    '''List advisories from the local database.'''
    _require_db(db)
    conn = db_mod.connect_db(db)
    _require_table(conn, db)
    resolved = list(states) if states else list(db_mod.DEFAULT_STATES)
    advisories = db_mod.query_advisories(conn, repo, resolved,
                                         severity, past_embargo, synced)
    if as_json:
        json.dump(advisories, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        _print_table(advisories)


@cli.command()
@click.argument('ghsa_id')
@click.option('--db', default=_DEFAULT_DB, metavar='PATH', show_default=True,
              help='local database file')
@click.option('--json', 'as_json', is_flag=True, help='emit raw JSON')
def show(ghsa_id: str, db: str, as_json: bool) -> None:
    '''Show a single advisory by GHSA id.'''
    _require_db(db)
    conn = db_mod.connect_db(db)
    _require_table(conn, db)
    advisory = db_mod.get_advisory(conn, ghsa_id)
    if as_json:
        json.dump(advisory, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        _print_advisory(advisory)


@cli.command()
@click.option('--email', required=True, metavar='FILE',
              help='vulnerability report email; use - for stdin')
@click.option('--output', default='./advisories', metavar='DIR',
              show_default=True, help='directory for generated files')
@click.option('--model', default=gen_mod.DEFAULT_MODEL, show_default=True,
              help='OpenRouter model to use')
@click.option('--embargo', metavar='DATE',
              help='embargo date as YYYY-MM-DD (default: today + 90 days)')
@click.option('--stdout', 'to_stdout', is_flag=True,
              help='print the advisory to stdout instead of writing files')
def generate(email: str, output: str, model: str,
             embargo: Optional[str], to_stdout: bool) -> None:
    '''Generate a GHSA advisory document from a vulnerability report email.'''
    embargo_date = embargo or (date.today() + timedelta(days=90)).isoformat()

    click.echo('Reading email…', err=True)
    email_content = gen_mod.read_email(email)

    click.echo(f'Calling OpenRouter ({model})…', err=True)
    raw_response = gen_mod.call_openrouter(email_content, model)

    advisory_body, metadata = gen_mod.split_advisory_and_metadata(raw_response)
    full_advisory = gen_mod.build_full_advisory(advisory_body, embargo_date)

    affected_files = (metadata or {}).get('affected_files') or []
    if affected_files:
        click.echo('Looking up maintainers…', err=True)
    collaborators = maint_mod.collect_collaborators(affected_files)
    if collaborators:
        click.echo(f'Collaborators: {", ".join(collaborators)}', err=True)

    github_json = gen_mod.build_github_json(metadata, full_advisory, collaborators)

    if to_stdout:
        click.echo(full_advisory)
        return

    slug = gen_mod.make_slug(metadata)
    advisory_path, json_path = gen_mod.write_output(
        full_advisory, github_json, output, slug)
    click.echo(f'Advisory   : {advisory_path}', err=True)
    click.echo(f'GitHub JSON: {json_path}', err=True)
    if metadata:
        click.echo(f'Summary    : {metadata.get("summary", "(none)")}', err=True)
        click.echo(f'Severity   : {metadata.get("severity", "(none)")}', err=True)
        click.echo(f'Embargo    : {embargo_date}', err=True)


@cli.command()
@click.argument('json_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--repo', default=gh_mod.DEFAULT_REPO, show_default=True,
              help='GitHub owner/name repo slug')
def create(json_file: str, repo: str) -> None:
    '''Create a draft advisory on GitHub from a JSON file.'''
    try:
        with open(json_file, 'r', encoding='utf-8') as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise click.ClickException(f'cannot read JSON file: {exc}')

    # collaborating_teams/users are only accepted by the update endpoint,
    # so split them out of the create payload and apply them via PATCH.
    collaborators = {k: payload.pop(k) for k in
                     ('collaborating_teams', 'collaborating_users')
                     if k in payload}

    session = gh_mod.github_session()
    advisory = gh_mod.post_advisory(payload, repo, session)
    ghsa_id = advisory.get('ghsa_id')
    click.echo(f'Created : {ghsa_id or "(unknown)"}')
    if advisory.get('html_url'):
        click.echo(f'URL     : {advisory["html_url"]}')

    if collaborators and ghsa_id:
        gh_mod.patch_advisory(ghsa_id, collaborators, repo, session)
        added = ', '.join(
            collaborators.get('collaborating_teams', [])
            + collaborators.get('collaborating_users', []))
        click.echo(f'Collaborators added: {added}')


@cli.command()
@click.option('--db', default=_DEFAULT_DB, metavar='PATH', show_default=True,
              help='local database file')
@click.option('--repo', default=gh_mod.DEFAULT_REPO, show_default=True,
              help='filter by repo slug')
@click.option('--output', '-o', default='advisories-dashboard.html',
              metavar='FILE', show_default=True,
              help='output HTML file')
@click.option('--open', 'open_browser', is_flag=True,
              help='open the dashboard in a browser after writing it')
def dashboard(db: str, repo: str, output: str, open_browser: bool) -> None:
    '''Render an HTML dashboard of the advisory database.'''
    _require_db(db)
    conn = db_mod.connect_db(db)
    _require_table(conn, db)
    advisories = db_mod.query_advisories(
        conn, repo, list(db_mod.ALL_STATES), severity=None, past_embargo=False)
    if not advisories:
        raise click.ClickException(
            f'no advisories for {repo} in {db}; run `ghsa sync` first')

    generated_at = datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')
    html_doc = dash_mod.render_dashboard(advisories, repo, generated_at)
    with open(output, 'w', encoding='utf-8') as fh:
        fh.write(html_doc)

    click.echo(f'Dashboard written to {output} ({len(advisories)} advisories)')
    if open_browser:
        webbrowser.open(f'file://{os.path.abspath(output)}')
