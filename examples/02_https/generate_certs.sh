#!/usr/bin/env bash
# generate_certs.sh — Generate a self-signed TLS certificate for local testing.
#
# Produces:
#   server.key   — RSA private key (2048-bit)
#   server.crt   — Self-signed X.509 certificate (valid 1 year)
#   dhparam.pem  — Diffie-Hellman parameters (2048-bit)
#
# Usage:
#   bash generate_certs.sh
#
# Requires openssl to be installed.

set -euo pipefail

echo "Generating RSA private key (server.key)..."
openssl genrsa -out server.key 2048

echo "Generating self-signed certificate (server.crt, valid 365 days)..."
openssl req -new -x509 \
    -key server.key \
    -out server.crt \
    -days 365 \
    -subj "/C=US/ST=State/L=City/O=libwebem Example/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Generating DH parameters (dhparam.pem, 2048-bit — this may take a moment)..."
openssl dhparam -out dhparam.pem 2048

echo ""
echo "Done. Files created:"
echo "  server.key   — private key"
echo "  server.crt   — self-signed certificate"
echo "  dhparam.pem  — DH parameters"
echo ""
echo "Run the server:  ./https_server"
echo "Test:            curl -k https://localhost:8443/api/secure"
