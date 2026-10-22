#!/bin/sh
# Dump the ghsa database to backups/ghsa-YYYY-MM-DD.sql.gz and keep the
# last KEEP_DAYS (default 30) days. Meant to run from cron, e.g.:
#   15 3 * * * /path/to/deploy/mysql/backup.sh
set -eu

cd "$(dirname "$0")"
umask 077
mkdir -p backups
out="backups/ghsa-$(date +%F).sql.gz"

docker compose exec -T mysql sh -c \
    'mysqldump -uroot -p"$(cat /run/secrets/root_pw)" --single-transaction ghsa' \
    | gzip > "$out.tmp"
mv "$out.tmp" "$out"

find backups -name 'ghsa-*.sql.gz' -mtime +"${KEEP_DAYS:-30}" -delete
