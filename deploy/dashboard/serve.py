#!/usr/bin/env python3
# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''Serve the advisory dashboard and regenerate it on a schedule.

At startup and at each time in UPDATE_TIMES (container local time, set TZ
to change it) this runs `ghsa sync` followed by `ghsa dashboard`, then
swaps the new page in. A failed sync is logged and the dashboard is still
rendered from what the database already holds. A failed render is retried
every RETRY_MINUTES until it succeeds.
'''

import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUTPUT_DIR = os.environ.get('OUTPUT_DIR', '/srv/dashboard')
PAGE = os.path.join(OUTPUT_DIR, 'index.html')
PORT = int(os.environ.get('PORT', '8080'))
UPDATE_TIMES = os.environ.get('UPDATE_TIMES', '06:00,18:00')
SYNC = os.environ.get('SYNC', 'true').lower() in ('1', 'true', 'yes')
REPO = os.environ.get('REPO')
RETRY = timedelta(minutes=int(os.environ.get('RETRY_MINUTES', '5')))

last_error: str = ''


def log(msg: str) -> None:
    print(f'{datetime.now().astimezone().isoformat(timespec="seconds")} '
          f'{msg}', flush=True)


def parse_times(spec: str) -> list[tuple[int, int]]:
    times = []
    for item in spec.replace(' ', '').split(','):
        if item:
            hour, minute = item.split(':')
            times.append((int(hour), int(minute)))
    if not times:
        sys.exit('error: UPDATE_TIMES is empty')
    return sorted(times)


def next_run(times: list[tuple[int, int]], now: datetime) -> datetime:
    for day in (0, 1):
        for hour, minute in times:
            candidate = (now + timedelta(days=day)).replace(
                hour=hour, minute=minute, second=0, microsecond=0)
            if candidate > now:
                return candidate
    raise AssertionError('unreachable')


def ghsa(*args: str) -> bool:
    repo = ['--repo', REPO] if REPO else []
    result = subprocess.run([sys.executable, '-m', 'ghsa', *args, *repo])
    if result.returncode:
        log(f'ghsa {args[0]} failed with exit status {result.returncode}')
    return result.returncode == 0


def update() -> bool:
    global last_error
    if SYNC:
        log('syncing advisories from GitHub')
        ghsa('sync')
    log('rendering dashboard')
    tmp = PAGE + '.tmp'
    if not ghsa('dashboard', '--output', tmp):
        last_error = f'last update failed at {datetime.now():%Y-%m-%d %H:%M}'
        return False
    os.replace(tmp, PAGE)
    last_error = ''
    log('dashboard updated')
    return True


def scheduler(times: list[tuple[int, int]]) -> None:
    ok = update()
    while True:
        when = next_run(times, datetime.now())
        if not ok:
            when = min(when, datetime.now() + RETRY)
        log(f'next update at {when:%Y-%m-%d %H:%M}')
        time.sleep(max(0, (when - datetime.now()).total_seconds()))
        ok = update()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._serve(body=True)

    def do_HEAD(self) -> None:
        self._serve(body=False)

    def _serve(self, body: bool) -> None:
        path = self.path.split('?', 1)[0]
        if path == '/healthz':
            self._send(HTTPStatus.OK, b'ok\n', 'text/plain', body)
            return
        if path not in ('/', '/index.html'):
            self._send(HTTPStatus.NOT_FOUND, b'not found\n', 'text/plain',
                       body)
            return
        try:
            with open(PAGE, 'rb') as fh:
                content = fh.read()
        except FileNotFoundError:
            msg = (f'dashboard generation failed ({last_error}); '
                   'see the container logs\n' if last_error
                   else 'dashboard is being generated, retry shortly\n')
            self._send(HTTPStatus.SERVICE_UNAVAILABLE, msg.encode(),
                       'text/plain', body)
            return
        self._send(HTTPStatus.OK, content, 'text/html; charset=utf-8', body)

    def _send(self, status: HTTPStatus, content: bytes, ctype: str,
              body: bool) -> None:
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        if body:
            self.wfile.write(content)

    def log_message(self, format: str, *args: object) -> None:
        log(f'{self.address_string()} {format % args}')


def main() -> None:
    times = parse_times(UPDATE_TIMES)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    threading.Thread(target=scheduler, args=(times,), daemon=True).start()
    log(f'serving on port {PORT}, updates at {UPDATE_TIMES}')
    ThreadingHTTPServer(('', PORT), Handler).serve_forever()


if __name__ == '__main__':
    main()
