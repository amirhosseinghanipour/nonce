#!/usr/bin/env bash
# Generate a dev RSA private key for JWT signing. Usage: ./scripts/gen-dev-jwt-key.sh
set -e
OUT="${1:-./scripts/dev-jwt-private.pem}"
openssl genrsa -out "$OUT" 2048
chmod 600 "$OUT"
echo "Wrote $OUT"
