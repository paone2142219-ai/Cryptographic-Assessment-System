#!/usr/bin/env bash
# deploy.sh — orchestrazione end-to-end del laboratorio:
#   1. genera la PKI di laboratorio (CA + certificati leaf)
#   2. costruisce le immagini Docker custom
#   3. avvia il laboratorio Kathará
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "═══ 1/3 — Generazione PKI ═══"
./gen_pki.sh

echo "═══ 2/3 — Build immagini Docker ═══"
./build_images.sh

echo "═══ 3/3 — Avvio laboratorio Kathará ═══"
kathara lstart

echo
echo "Laboratorio avviato. Alcuni comandi utili:"
echo "  kathara connect clientext   # apri una shell su clientext"
echo "  kathara connect bastion     # apri una shell sul bastion"
echo "  ls shared/                  # dati grezzi raccolti dai sensori, per hostname"
echo "  kathara lclean              # ferma e ripulisce il laboratorio"
