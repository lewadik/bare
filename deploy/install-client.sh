#!/bin/sh
# Install the Haven client on a Linux server that should be backed up.
#
#   sudo ./install-client.sh [profile]
#
# Then edit /etc/haven/client.toml (created from the example on first run),
# run `haven --profile <profile> check`, and enable the timer:
#
#   sudo systemctl enable --now haven-backup@<profile>.timer
#   sudo systemctl enable --now haven-maintenance@<profile>.timer
set -eu

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

PROFILE=${1:-system}
SRC=$(cd "$(dirname "$0")/.." && pwd)

install -d -m 0755 /etc/haven
install -d -m 0755 /etc/haven/tls
install -d -m 0700 /var/cache/haven
install -d -m 0750 /var/log/haven
make -C "$SRC" install

if [ ! -f /etc/haven/client.toml ]; then
    install -m 0600 "$SRC/deploy/client.toml.example" /etc/haven/client.toml
    echo "created /etc/haven/client.toml from the example — fill in url/token/secret"
fi

for unit in haven-backup@.service haven-backup@.timer haven-maintenance@.service \
            haven-maintenance@.timer haven-verify@.service haven-verify@.timer; do
    install -m 0644 "$SRC/deploy/$unit" /etc/systemd/system/"$unit"
done
install -m 0644 "$SRC/deploy/logrotate-haven" /etc/logrotate.d/haven
systemctl daemon-reload

cat <<EOF

Haven client installed.

  1. Edit /etc/haven/client.toml (profile: $PROFILE).
     Use the token and repository secret handed out by the server operator;
     `haven init` is not needed because the file already exists.

  2. Check the connection:
       haven --config /etc/haven/client.toml --profile $PROFILE check

  3. Take a first backup in the foreground and watch it:
       haven --config /etc/haven/client.toml --profile $PROFILE backup

  4. Enable the schedule:
       systemctl enable --now haven-backup@$PROFILE.timer
       systemctl enable --now haven-maintenance@$PROFILE.timer

  5. Prove a restore works (do this now, not during an incident):
       haven ... snapshots
       haven ... restore <snapshot> --to /var/tmp/restore-test

Logs: journalctl -u haven-backup@$PROFILE -n 50 --no-pager
EOF
