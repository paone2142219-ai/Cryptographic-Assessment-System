#!/usr/bin/env bash
# vici_collector.sh — raccolta ATTIVA e periodica dello stato delle SA IPsec
# via l'interfaccia VICI di strongSwan, più una copia della configurazione
# statica dichiarata.
#
# Motivazione generale: IKE_AUTH (che negozia la Child SA, cioè gli
# algoritmi ESP del piano dati) avviene già dentro il canale cifrato dalla
# IKE SA — non è osservabile da uno sniffer passivo come Zeek. L'unica
# fonte in grado di fornire visibilità genuina è l'endpoint stesso,
# interrogato direttamente.
#
# Tre fonti, tre file, perché sono complementari e non sovrapponibili:
#   - `swanctl --list-sas`   -> ipsec_status.txt   — stato DELLE SA ATTIVE
#     in questo istante (algoritmi negoziati, se la PFS è stata osservata
#     su questo specifico rekey, ...).
#   - `swanctl --list-conns` -> ipsec_conns.txt     — metadati della
#     CONFIGURAZIONE (metodo di autenticazione, rekey time configurato).
#   - i file /etc/swanctl/conf.d/*.conf stessi -> swanctl_config.txt —
#     copia grezza della configurazione DICHIARATA, incluse le proposte
#     complete (es. "aes256gcm16-ecp384"). Serve a rendere esplicito il
#     confronto dichiarato/osservato per la PFS: un gruppo DH presente
#     nella proposta ESP dichiarata ma assente nella Child SA osservata
#     non è un errore di configurazione — è la conseguenza strutturale
#     del fatto che la primissima Child SA, negoziata dentro IKE_AUTH,
#     non porta mai un payload KE (vedi ipsec_parser.py per il dettaglio).
#
# Nessuna delle tre fonti espone mai il segreto PSK stesso: swanctl non lo
# mostra in nessun comando, e i file conf.d referenziano solo il NOME del
# metodo di autenticazione, mai il valore (il segreto vive solo in
# secrets.conf, mai raccolto da questo script).
#
# Tutti i file contengono testo grezzo (non JSON: nessuna elaborazione
# applicata qui, la raccolta è deliberatamente "grezza" — l'interpretazione
# è demandata a pipeline_cbom, non a questo script).
set -euo pipefail

HOST_TAG="$(hostname)"
OUT_DIR="/shared/${HOST_TAG}"
SAS_FILE="${OUT_DIR}/ipsec_status.txt"
CONNS_FILE="${OUT_DIR}/ipsec_conns.txt"
CONFIG_FILE="${OUT_DIR}/swanctl_config.txt"
CONF_DIR="/etc/swanctl/conf.d"
INTERVAL="${VICI_COLLECT_INTERVAL:-30}"

mkdir -p "$OUT_DIR"

echo "[vici_collector] avvio raccolta attiva su ${HOST_TAG}, intervallo ${INTERVAL}s"
echo "[vici_collector]   SA attive           -> ${SAS_FILE}"
echo "[vici_collector]   config. connessioni -> ${CONNS_FILE}"
echo "[vici_collector]   config. dichiarata  -> ${CONFIG_FILE}"

while true; do
    if swanctl --list-sas > "${SAS_FILE}.tmp" 2>/dev/null; then
        mv -f "${SAS_FILE}.tmp" "${SAS_FILE}"
    else
        echo "[vici_collector] swanctl --list-sas fallito, riprovo al prossimo ciclo" >&2
        rm -f "${SAS_FILE}.tmp"
    fi

    if swanctl --list-conns > "${CONNS_FILE}.tmp" 2>/dev/null; then
        mv -f "${CONNS_FILE}.tmp" "${CONNS_FILE}"
    else
        echo "[vici_collector] swanctl --list-conns fallito, riprovo al prossimo ciclo" >&2
        rm -f "${CONNS_FILE}.tmp"
    fi

    # Copia grezza dei file di configurazione statica — non richiede VICI,
    # è una semplice lettura di file, ma sta in questo stesso loop per
    # tenere tutte e tre le fonti aggiornate insieme e nello stesso posto.
    if [ -d "$CONF_DIR" ]; then
        cat "${CONF_DIR}"/*.conf > "${CONFIG_FILE}.tmp" 2>/dev/null && \
            mv -f "${CONFIG_FILE}.tmp" "${CONFIG_FILE}" || rm -f "${CONFIG_FILE}.tmp"
    fi

    sleep "$INTERVAL"
done
