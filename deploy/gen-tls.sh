#!/bin/sh
# Create a small private CA and a server certificate for havend.
#
#   ./gen-tls.sh backup.example.com [/etc/haven/tls]
#
# Client hosts need ca.crt (ca_file in their profile); the server needs
# server.crt + server.key. Keep ca.key offline once your fleet is enrolled:
# anyone with it can issue a certificate your clients will trust.
set -eu

HOST=${1:-}
OUT=${2:-/etc/haven/tls}

if [ "$HOST" = "--new-ca" ]; then
    HOST=${2:-}
    OUT=${3:-/etc/haven/tls}
    NEW_CA=1
else
    NEW_CA=0
fi

if [ -z "$HOST" ]; then
    echo "usage: $0 [--new-ca] <hostname-or-ip> [output-dir]" >&2
    exit 2
fi

umask 077
mkdir -p "$OUT"

if [ "$NEW_CA" = "1" ] || [ ! -f "$OUT/ca.key" ] || [ ! -f "$OUT/ca.crt" ]; then
    rm -f "$OUT/ca.key" "$OUT/ca.crt"
    openssl genrsa -out "$OUT/ca.key" 4096
    openssl req -x509 -new -nodes -key "$OUT/ca.key" -sha256 -days 3650 \
        -subj "/CN=Haven private CA ($(hostname -s 2>/dev/null || echo host))" \
        -out "$OUT/ca.crt"
else
    echo "reusing the existing CA in $OUT (clients keep trusting it)"
fi

openssl genrsa -out "$OUT/server.key" 3072
openssl req -new -key "$OUT/server.key" -subj "/CN=$HOST" -out "$OUT/server.csr"

cat > "$OUT/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$HOST,IP:$HOST
EOF

openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/server.crt" -days 825 -sha256 -extfile "$OUT/server.ext"

rm -f "$OUT/server.csr" "$OUT/server.ext"
chmod 600 "$OUT/ca.key" "$OUT/server.key"
chmod 644 "$OUT/ca.crt" "$OUT/server.crt"

# When run as root on the repository host, hand the material to the daemon user
# so `havend` (User=haven) can read the key without extra steps.
if [ "$(id -u)" = 0 ] && id haven >/dev/null 2>&1; then
    chown -R haven:haven "$OUT"
    chmod 600 "$OUT/ca.key" "$OUT/server.key"
fi

echo "wrote:"
echo "  $OUT/ca.crt      (distribute to every client as ca_file)"
echo "  $OUT/server.crt  (server tls_cert)"
echo "  $OUT/server.key  (server tls_key, mode 0600)"
echo
echo "Check it with: openssl x509 -in $OUT/server.crt -noout -subject -ext subjectAltName"
