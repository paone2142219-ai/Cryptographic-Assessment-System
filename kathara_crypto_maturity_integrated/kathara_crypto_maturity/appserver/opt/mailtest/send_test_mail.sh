#!/usr/bin/env bash
# send_test_mail.sh — invia un messaggio di prova ad mailsrv forzando STARTTLS,
# per generare traffico SMTP/TLS osservabile da Zeek (dmzgw/internalgw).
set -euo pipefail

MAILSRV="10.1.0.11"

swaks --to root@katharalab.local \
      --from appserver@katharalab.local \
      --server "$MAILSRV" \
      --port 25 \
      --tls \
      --tls-verify \
      --tls-ca-path /etc/pki/ca.pem \
      --header "Subject: Test SMTP/STARTTLS" \
      --body "Messaggio di prova per la raccolta di telemetria crittografica." \
      || echo "[send_test_mail] invio fallito — controllare connettività verso $MAILSRV"
