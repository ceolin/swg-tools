#!/bin/sh
# Generate the passwords and TLS certificates for the ghsa MySQL server.
#
# Usage: ./setup.sh HOSTNAME [EXTRA_NAME_OR_IP...]
#
# HOSTNAME (and any extra names/IPs) go into the server certificate, so
# clients must connect using one of them.
set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 HOSTNAME [EXTRA_NAME_OR_IP...]" >&2
    exit 1
fi
host=$1

cd "$(dirname "$0")"
umask 077
mkdir -p secrets certs

# The container runs mysqld as uid 999, so the mounted files must be
# world-readable; the 0700 directories keep them private on the host.
for name in root_pw ghsa_pw; do
    if [ ! -s "secrets/$name" ]; then
        openssl rand -hex 24 > "secrets/$name"
    fi
done

if [ ! -s certs/server-cert.pem ]; then
    san=""
    for name in "$@"; do
        case $name in
            *[!0-9.]*) san="$san,DNS:$name" ;;
            *) san="$san,IP:$name" ;;
        esac
    done
    san=${san#,}

    openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
        -subj "/CN=ghsa MySQL CA" \
        -keyout certs/ca-key.pem -out certs/ca.pem 2>/dev/null
    openssl req -newkey rsa:3072 -nodes \
        -subj "/CN=$host" \
        -keyout certs/server-key.pem -out certs/server.csr 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san" \
        > certs/server.ext
    openssl x509 -req -in certs/server.csr -days 825 \
        -CA certs/ca.pem -CAkey certs/ca-key.pem -CAcreateserial \
        -extfile certs/server.ext -out certs/server-cert.pem 2>/dev/null
    rm -f certs/server.csr certs/server.ext certs/ca.srl
fi

chmod 644 secrets/root_pw secrets/ghsa_pw \
    certs/ca.pem certs/server-cert.pem certs/server-key.pem

cat <<MSG
Secrets and certificates are in $(pwd)/secrets and $(pwd)/certs.

Start the server:
    docker compose up -d

Give each client a copy of certs/ca.pem and set:
    export GHSA_DATABASE_URL='mysql://ghsa:$(cat secrets/ghsa_pw)@$host:${MYSQL_PORT:-3306}/ghsa?ssl_ca=/path/to/ca.pem'
MSG
