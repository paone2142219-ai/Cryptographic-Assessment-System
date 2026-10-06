"""
ssh_parser.py — Parser dedicato ai log SSH di Zeek

Responsabilità:
  - Lettura e parsing del file ssh.log prodotto da Zeek
  - Estrazione dei campi crittograficamente rilevanti:
      versione SSH, cipher, MAC, kex algorithm, host key algorithm
  - Restituzione di una lista di record intermedi (dict)

Schema del record intermedio SSH:
  {
    "ts":             float   — timestamp UNIX
    "uid":            str     — Zeek connection UID
    "src_ip":         str     — IP sorgente
    "src_port":       int
    "dst_ip":         str     — IP destinazione
    "dst_port":       int
    "ssh_version":    int     — 1 o 2
    "client_banner":  str|None  — es. "SSH-2.0-OpenSSH_9.0"
    "server_banner":  str|None
    "cipher_alg":     str|None   — es. "aes256-ctr"
    "mac_alg":        str|None   — es. "hmac-sha2-256"
    "kex_alg":        str|None   — es. "curve25519-sha256"
    "host_key_alg":   str|None   — es. "ecdsa-sha2-nistp256" (algoritmo)
    "host_key":       str|None   — fingerprint della specifica host key
                       presentata (campo Zeek "host_key"). Distinto da
                       host_key_alg: due host con lo stesso algoritmo
                       hanno fingerprint diversi. Necessario per
                       rilevare rotazione/cambio di chiave in un
                       modello TOFU (Trust On First Use).
    "compression_alg": str|None  — es. "none", "zlib@openssh.com"
    "auth_success":   bool
    "auth_attempts":  int     — numero di tentativi di autenticazione
                       (campo Zeek "auth_attempts"). Prima di questa
                       fix non veniva letto: il rilevamento brute-force
                       nel normalizzatore era codice morto (il campo
                       arrivava sempre assente e ripiegava sul default).
    "direction":      str|None
  }
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = {
    "ts", "uid", "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p", "version",
}


def parse(log_path: str) -> list[dict]:
    """
    Legge il file ssh.log di Zeek e restituisce una lista
    di record SSH intermedi.

    Args:
        log_path: percorso assoluto al file ssh.log.

    Returns:
        Lista di dizionari con i campi SSH estratti.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"[SSHParser] File non trovato: {log_path}")

    records: list[dict] = []
    field_names: list[str] = []
    separator: str = "\t"

    with path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")

            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1]
                separator = bytes(sep, "utf-8").decode("unicode_escape")
                continue
            if line.startswith("#fields"):
                field_names = line.split(separator)[1:]
                _check_required_fields(field_names, log_path)
                continue

            if line.startswith("#"):
                continue

            if not line.strip():
                continue

            parts = line.split(separator)

            if len(parts) != len(field_names):
                logger.warning(
                    f"[SSHParser] Riga malformata (attesi {len(field_names)} "
                    f"campi, trovati {len(parts)}): {line[:80]}"
                )
                continue

            row = dict(zip(field_names, parts))
            record = _extract_record(row)

            if record:
                records.append(record)

    logger.info(f"[SSHParser] Estratti {len(records)} record da {path.name}")
    return records


# ── Helpers ────────────────────────────────────────────────────────────────────

def _check_required_fields(fields: list[str], path: str) -> None:
    missing = REQUIRED_FIELDS - set(fields)
    if missing:
        logger.warning(
            f"[SSHParser] Campi mancanti in {path}: {missing}. "
            "Alcuni record potrebbero essere incompleti."
        )


def _optional(value: str) -> str | None:
    return None if value in ("-", "(empty)", "") else value


def _extract_record(row: dict) -> dict | None:
    try:
        return {
            "ts":              float(row.get("ts", 0)),
            "uid":             row.get("uid", ""),
            "src_ip":          row.get("id.orig_h", ""),
            "src_port":        _to_int(row.get("id.orig_p")),
            "dst_ip":          row.get("id.resp_h", ""),
            "dst_port":        _to_int(row.get("id.resp_p")),
            "ssh_version":     _to_int(row.get("version"), default=2),
            "client_banner":   _optional(row.get("client", "-")),
            "server_banner":   _optional(row.get("server", "-")),
            "cipher_alg":      _optional(row.get("cipher_alg", "-")),
            "mac_alg":         _optional(row.get("mac_alg", "-")),
            "kex_alg":         _optional(row.get("kex_alg", "-")),
            "host_key_alg":    _optional(row.get("host_key_alg", "-")),
            "host_key":        _optional(row.get("host_key", "-")),
            "compression_alg": _optional(row.get("compression_alg", "-")),
            "auth_success":    _parse_bool(row.get("auth_success", "F")),
            "auth_attempts":   _to_int(row.get("auth_attempts"), default=1),
            "direction":       _optional(row.get("direction", "-")),
        }
    except Exception as exc:
        logger.error(f"[SSHParser] Errore parsing riga: {exc} — {row}")
        return None


def _to_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_bool(value: str) -> bool:
    return value.upper() in ("T", "TRUE", "1", "YES")
