#!/usr/bin/env bash
# run_backup.sh — trasferisce l'archivio di backup verso backupsrv via SFTP,
# usando l'autenticazione a chiave pubblica dedicata (utente backupuser).
set -euo pipefail

SRC_DIR="/var/www/data"
DEST_HOST="10.2.0.11"
DEST_USER="backupuser"
TS="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="/tmp/backup-${TS}.tar.gz"

tar -czf "$ARCHIVE" -C "$SRC_DIR" .

sftp -i /root/.ssh/id_ed25519 \
     -o StrictHostKeyChecking=accept-new \
     -o IdentitiesOnly=yes \
     "${DEST_USER}@${DEST_HOST}" <<EOF
cd incoming
put ${ARCHIVE}
bye
EOF

rm -f "$ARCHIVE"
echo "[run_backup] backup ${TS} trasferito su ${DEST_HOST}:incoming/"
