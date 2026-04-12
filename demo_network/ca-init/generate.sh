#!/usr/bin/env bash
# Generates a test CA + one SAN leaf certificate covering every hostname used
# inside the demo network. Output goes to /certs (a shared Docker volume).
# Idempotent: if ca.crt already exists and is valid, does nothing.
set -euo pipefail

OUT=/certs
mkdir -p "$OUT"

if [[ -f "$OUT/ca.crt" && -f "$OUT/traefik.crt" && -f "$OUT/traefik.key" ]]; then
    # Verify the CA is still valid for at least 30 days.
    if openssl x509 -in "$OUT/ca.crt" -noout -checkend $((30*24*3600)) >/dev/null 2>&1; then
        echo "ca-init: certs already present and valid, skipping"
        exit 0
    fi
    echo "ca-init: existing cert expiring within 30 days, regenerating"
fi

umask 077

# ── Root CA ──────────────────────────────────────────────────────────────────
openssl genrsa -out "$OUT/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/ca.key" -sha256 -days 3650 \
    -subj "/CN=Cullis Demo Network Test CA/O=Cullis Demo" \
    -out "$OUT/ca.crt"

# ── Traefik leaf (multi-SAN for every host in the demo) ──────────────────────
HOSTS=(
    "broker.cullis.test"
    "proxy-a.cullis.test"
    "proxy-b.cullis.test"
    "checker.cullis.test"
)

SAN_CONF="$(mktemp)"
{
    echo "[req]"
    echo "distinguished_name = dn"
    echo "req_extensions = v3_req"
    echo "prompt = no"
    echo ""
    echo "[dn]"
    echo "CN = ${HOSTS[0]}"
    echo "O = Cullis Demo"
    echo ""
    echo "[v3_req]"
    echo "keyUsage = critical, digitalSignature, keyEncipherment"
    echo "extendedKeyUsage = serverAuth"
    echo "subjectAltName = @alt"
    echo ""
    echo "[alt]"
    i=1
    for h in "${HOSTS[@]}"; do
        echo "DNS.$i = $h"
        i=$((i+1))
    done
} > "$SAN_CONF"

openssl genrsa -out "$OUT/traefik.key" 2048 2>/dev/null
openssl req -new -key "$OUT/traefik.key" -out "$OUT/traefik.csr" -config "$SAN_CONF"

openssl x509 -req -in "$OUT/traefik.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/traefik.crt" -days 365 -sha256 \
    -extfile "$SAN_CONF" -extensions v3_req 2>/dev/null

rm -f "$OUT/traefik.csr" "$SAN_CONF" "$OUT/ca.srl"

# Make files world-readable so non-root services can read ca.crt + leaf
chmod 644 "$OUT/ca.crt" "$OUT/traefik.crt"
chmod 640 "$OUT/traefik.key"

echo "ca-init: generated test CA + leaf for: ${HOSTS[*]}"
openssl x509 -in "$OUT/ca.crt" -noout -subject -issuer -dates
