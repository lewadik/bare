#!/bin/sh
# Install havend (the repository server) on a Debian/RHEL-like Linux host.
#
#   sudo ./install-server.sh
#
# Idempotent: re-running upgrades the code and units but never touches an
# existing repository or configuration.
set -eu

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

SRC=$(cd "$(dirname "$0")/.." && pwd)

if ! id haven >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/haven --shell /usr/sbin/nologin --no-create-home haven
fi

install -d -m 0770 -o root -g haven /etc/haven
install -d -m 0750 -o root -g haven /etc/haven/tls
install -d -m 0750 -o haven -g haven /var/lib/haven
install -d -m 0700 -o haven -g haven /var/lib/haven/repo

# The daemon runs as `haven` and must be able to rewrite these two files.
if [ ! -f /etc/haven/repo.secret ]; then
    : > /etc/haven/repo.secret
fi
chown haven:haven /etc/haven/repo.secret
chmod 0600 /etc/haven/repo.secret
if [ ! -f /etc/haven/tokens.json ]; then
    printf '{"version":1,"tokens":[]}\n' > /etc/haven/tokens.json
fi
chown haven:haven /etc/haven/tokens.json
chmod 0600 /etc/haven/tokens.json

make -C "$SRC" install

install -m 0644 "$SRC/deploy/haven-server.service" /etc/systemd/system/haven-server.service

if [ ! -f /etc/haven/server.toml ]; then
    install -m 0640 -o root -g haven "$SRC/deploy/server.toml.example" /etc/haven/server.toml
fi

systemctl daemon-reload
systemctl enable haven-server.service

cat <<'EOF'

havend is installed. Finish the setup:

  1. TLS (unless you terminate it in nginx):
       deploy/gen-tls.sh backup.example.com
     then set tls_cert / tls_key in /etc/haven/server.toml.

  2. Create the repository (prints the repository secret once):
       sudo -u haven havend --config /etc/haven/server.toml init --name primary

  3. Create one token per client host:
       sudo -u haven havend --config /etc/haven/server.toml token add \
            --name web-01 --scope backup

  4. Start the daemon and open the port only to your backup network:
       systemctl start haven-server
       firewall-cmd --add-service=... (or an nftables rule for tcp/8443)

  5. On each client:
       sudo ./deploy/install-client.sh system
     then edit /etc/haven/client.toml (url, token, secret) and run:
       haven --config /etc/haven/client.toml --profile system check
     docs/operations.md section 3 has the details.

Verify with:
  systemctl status haven-server
  curl --cacert /etc/haven/tls/ca.crt https://backup.example.com:8443/v1/health
EOF
