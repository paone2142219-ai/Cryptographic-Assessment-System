"""
tls_parser.py — Parser dedicato ai log TLS/SSL di Zeek

Responsabilità:
  - Lettura e parsing del file ssl.log (o tls.log) prodotto da Zeek
  - Estrazione dei campi crittograficamente rilevanti:
      versione TLS, cipher suite, curva ellittica, SNI, validazione cert
  - Restituzione di una lista di record intermedi (dict)

Schema del record intermedio TLS:
  {
    "ts":              float   — timestamp UNIX
    "uid":             str     — Zeek connection UID
    "src_ip":          str     — IP sorgente
    "src_port":        int
    "dst_ip":          str     — IP destinazione
    "dst_port":        int
    "tls_version":     str     — es. "TLSv12", "TLSv13"
    "cipher_suite":    str     — es. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    "curve":           str|None
    "server_name":     str|None
    "established":     bool
    "validation":      str|None
    "cert_chain_fps":  list[str] — fingerprint SHA-256 del certificate
                        chain (campo vector di ssl.log). Usato dal
                        normalizzatore per la correlazione ESATTA con
                        x509.log (vedi x509_parser.correlate_by_fingerprints).
                        Per TLS 1.3 è normale che sia vuoto: il messaggio
                        Certificate è cifrato nell'handshake e non
                        osservabile da uno sniffer passivo come Zeek.
    "resumed":         bool    — sessione ripresa (PSK/session ticket)
                        anziché full handshake. Rilevante per la PFS:
                        una ripresa TLS 1.3 puramente PSK (psk_ke, senza
                        key_share) non fornisce forward secrecy, a
                        differenza del psk_dhe_ke (che invece la fornisce
                        perché include comunque un (EC)DHE fresco). Zeek
                        non distingue le due modalità PSK; il segnale
                        osservabile usato come proxy è l'assenza del
                        gruppo/curva negoziata (campo "curve") — vedi
                        normalizer.normalize_tls().
  }
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Pattern di un timestamp UNIX Zeek (es. 1783246882.096882): 10 cifre intere
# + parte decimale. Usato per individuare il confine tra due record TLS
# fusi sulla stessa riga fisica per assenza del newline separatore.
_TS_PATTERN = re.compile(r"\d{9,10}\.\d+")

# Campi attesi nell'header #fields del log Zeek SSL
REQUIRED_FIELDS = {
    "ts", "uid", "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p", "version", "cipher",
}


def parse(log_path: str) -> list[dict]:
    """
    Legge il file ssl.log di Zeek e restituisce una lista
    di record TLS intermedi.

    Args:
        log_path: percorso assoluto al file ssl.log.

    Returns:
        Lista di dizionari con i campi TLS estratti.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"[TLSParser] File non trovato: {log_path}")

    records: list[dict] = []
    field_names: list[str] = []
    separator: str = "\t"

    with path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")

            # ── Intestazioni Zeek ──────────────────────────────────────
            if line.startswith("#separator"):
                sep_hex = line.split()[-1]
                separator = bytes.fromhex(sep_hex.replace("\\x", "")).decode()
                continue

            if line.startswith("#fields"):
                field_names = line.split(separator)[1:]
                _check_required_fields(field_names, log_path)
                continue

            if line.startswith("#"):
                continue  # altri metadati (#types, #open, ecc.)

            if not line.strip():
                continue

            # ── Parsing riga dati ──────────────────────────────────────
            parts = line.split(separator)

            if len(parts) != len(field_names):
                recovered = _recover_concatenated_rows(parts, field_names)

                if recovered is None:
                    logger.warning(
                        f"[TLSParser] Riga malformata (attesi {len(field_names)} "
                        f"campi, trovati {len(parts)}): {line[:80]}"
                    )
                    continue

                logger.warning(
                    f"[TLSParser] Riga fusa senza separatore: recuperati "
                    f"{len(recovered)} record da un'unica riga fisica "
                    f"(attesi {len(field_names)}, trovati {len(parts)} campi)."
                )
                for row_fields in recovered:
                    row = dict(zip(field_names, row_fields))
                    record = _extract_record(row)
                    if record:
                        records.append(record)
                continue

            row = dict(zip(field_names, parts))
            record = _extract_record(row)

            if record:
                records.append(record)

    logger.info(f"[TLSParser] Estratti {len(records)} record da {path.name}")
    return records


# ── Helpers ────────────────────────────────────────────────────────────────────

def _recover_concatenated_rows(
    parts: list[str], field_names: list[str]
) -> list[list[str]] | None:
    """
    Tenta di recuperare N record Zeek fusi su un'unica riga fisica per
    assenza del newline separatore (bug tipico di scritture non atomiche
    o concatenazioni di log senza trailing newline).

    Se k record da F campi ciascuno vengono fusi senza newline tra loro,
    lo split sul separatore di campo produce esattamente:
        T = F*k - (k-1)
    token, perché ad ogni confine l'ultimo campo del record i e il primo
    campo (ts) del record i+1 restano incollati in un unico token.

    Returns:
        Lista di record (ciascuno list[str] di F campi) se il recupero
        ha successo, altrimenti None.
    """
    f = len(field_names)
    t = len(parts)

    if f <= 1 or (t - 1) % (f - 1) != 0:
        return None  # non è un multiplo compatibile: non è questo il bug

    k = (t - 1) // (f - 1)
    if k <= 1:
        return None  # nessuna fusione rilevabile

    parts = list(parts)  # copia locale, modificabile in-place
    rows: list[list[str]] = []
    idx = 0

    for rec_i in range(k):
        row_fields = parts[idx: idx + (f - 1)]
        idx += f - 1

        boundary_token = parts[idx]

        if rec_i < k - 1:
            match = _TS_PATTERN.search(boundary_token)
            if not match or match.start() == 0:
                return None  # non trovo il confine atteso: rinuncio

            row_fields = row_fields + [boundary_token[: match.start()]]
            # Il resto del token (il ts del record successivo) resta
            # disponibile come primo campo della prossima iterazione.
            parts[idx] = boundary_token[match.start():]
        else:
            row_fields = row_fields + [boundary_token]
            idx += 1

        rows.append(row_fields)

    return rows


def _check_required_fields(fields: list[str], path: str) -> None:
    missing = REQUIRED_FIELDS - set(fields)
    if missing:
        logger.warning(
            f"[TLSParser] Campi mancanti in {path}: {missing}. "
            "Alcuni record potrebbero essere incompleti."
        )


def _optional(value: str) -> str | None:
    """Converte i segnaposto Zeek ('-', '(empty)') in None."""
    return None if value in ("-", "(empty)", "") else value


def _parse_vector(value: str | None) -> list[str]:
    """
    Decodifica un campo vector[string] di Zeek (es. cert_chain_fps),
    che usa la virgola come set_separator di default.
    """
    if not value or value in ("-", "(empty)"):
        return []
    return [v.strip() for v in value.split(",") if v.strip() and v.strip() != "-"]


def _extract_record(row: dict) -> dict | None:
    """Mappa una riga raw verso il record intermedio TLS."""
    try:
        return {
            "ts":              float(row.get("ts", 0)),
            "uid":             row.get("uid", ""),
            "src_ip":          row.get("id.orig_h", ""),
            "src_port":        _to_int(row.get("id.orig_p")),
            "dst_ip":          row.get("id.resp_h", ""),
            "dst_port":        _to_int(row.get("id.resp_p")),
            "tls_version":     _optional(row.get("version", "-")),
            "cipher_suite":    _optional(row.get("cipher", "-")),
            "curve":           _optional(row.get("curve", "-")),
            "server_name":     _optional(row.get("server_name", "-")),
            "established":     row.get("established", "F").upper() == "T",
            "validation":      _optional(row.get("validation_status", "-")),
            # Correlazione ESATTA col certificato in x509.log. Prima di
            # questa fix il campo non veniva letto affatto: ogni
            # connessione TLS finiva sempre sulla correlazione fallback
            # IP+timestamp (±5s), imprecisa per costruzione — vedi
            # normalizer.normalize_tls().
            "cert_chain_fps":  _parse_vector(row.get("cert_chain_fps")),
            "resumed":         row.get("resumed", "F").upper() == "T",
        }
    except Exception as exc:
        logger.error(f"[TLSParser] Errore parsing riga: {exc} — {row}")
        return None


def _to_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default