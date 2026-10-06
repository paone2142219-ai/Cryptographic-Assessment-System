"""
x509_parser.py — Parser dedicato al log x509.log di Zeek
═══════════════════════════════════════════════════════════

Responsabilità
──────────────
Legge il file x509.log prodotto da Zeek e restituisce una lista di
dizionari CertRecord, uno per ogni certificato osservato.

Caso d'uso principale: downgrade TLS 1.2
  Quando il negoziato scende a TLS 1.2 (o TLS 1.0/1.1), Zeek popola
  x509.log con i dettagli del certificato presentato dal server.
  Questo parser li estrae e li rende disponibili al normalizzatore TLS,
  che li allega al record di connessione tramite correlazione per UID.

Struttura attesa di x509.log (Zeek)
──────────────────────────────────
#fields  ts  fingerprint  certificate.version  certificate.serial
         certificate.subject  certificate.issuer
         certificate.not_valid_before  certificate.not_valid_after
         certificate.key_alg  certificate.sig_alg
         certificate.key_type  certificate.key_length  certificate.exponent
         certificate.curve
         san.dns  san.uri  san.email  san.ip
         basic_constraints.ca  basic_constraints.path_len
         host_cert  client_cert

Schema del record restituito (CertRecord)
──────────────────────────────────────────
{
    "ts":             float   — timestamp UNIX
    "fingerprint":    str     — SHA-256 del certificato (hex)
    "version":        int     — versione X.509 (1=v1, 3=v3)
    "serial":         str     — numero di serie (hex)
    "subject":        str     — DN soggetto
    "issuer":         str     — DN emittente
    "not_before":     str     — ISO 8601 UTC
    "not_after":      str     — ISO 8601 UTC
    "key_alg":        str     — algoritmo chiave (es. rsaEncryption)
    "sig_alg":        str     — algoritmo firma (es. sha256WithRSAEncryption)
    "key_type":       str     — tipo chiave (rsa, ec, dsa, …)
    "key_length":     int     — lunghezza chiave in bit
    "exponent":       str|None — esponente pubblico RSA
    "curve":          str|None — curva EC se applicabile
    "san_dns":        list[str]
    "san_uri":        list[str]
    "san_email":      list[str]
    "san_ip":         list[str]
    "is_ca":          bool    — basic_constraints.ca
    "path_len":       int|None
    "host_cert":      bool    — certificato server (leaf)
    "client_cert":    bool
    "status":         list[str] — [VALID|EXPIRED|SELF_SIGNED|WEAK_KEY|WEAK_SIG]
    "cia_impact":     list[str] — sempre ["AUTHENTICITY"] per i certificati
}

Correlazione con ssl.log
────────────────────────
Zeek non inserisce direttamente l'UID di connessione in x509.log.
La correlazione avviene per fingerprint: ssl.log (a partire da Zeek 4+)
include il campo cert_chain_fps (lista di fingerprint SHA-256).
Il normalizzatore TLS correla i due file usando quella lista.

Se ssl.log NON contiene cert_chain_fps (Zeek < 4 o log meno recenti),
la correlazione avviene per indirizzo IP server (id.resp_h) e timestamp
(finestra ±5 secondi) — logica di fallback implementata nel normalizzatore.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Campi minimi necessari
REQUIRED_FIELDS = {
    "ts", "fingerprint",
    "certificate.subject", "certificate.issuer",
    "certificate.key_type", "certificate.key_length",
    "certificate.sig_alg",
}

# Algoritmi di firma deboli (produce WEAK_SIG)
WEAK_SIG_ALGS = {
    "md5withrsa", "md5withrsa encryption",
    "sha1withrsa", "sha1withrsa encryption",
    "sha1withrsaencryption",
    "ecdsa-with-sha1",
    "dsawithsha1",
}

# Soglie chiave debole: { key_type -> min_bits_accettabile }
WEAK_KEY_THRESHOLDS: dict[str, int] = {
    "rsa": 2048,
    "dsa": 2048,
    "ec":  256,
    "ecdsa": 256,
}


# ── Entry point pubblico ──────────────────────────────────────────────────────

def parse(log_path: str) -> list[dict]:
    """
    Legge x509.log di Zeek e restituisce la lista di CertRecord.

    Args:
        log_path: percorso assoluto al file x509.log.

    Returns:
        Lista di dizionari CertRecord (vedi schema nel modulo docstring).

    Raises:
        FileNotFoundError: se il file non esiste.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(f"[X509Parser] File non trovato: {log_path}")

    records: list[dict] = []
    field_names: list[str] = []
    separator: str = "\t"

    with path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")

            # ── Header Zeek ────────────────────────────────────────────
            if line.startswith("#separator"):
                sep_hex = line.split()[-1]
                separator = bytes.fromhex(sep_hex.replace("\\x", "")).decode()
                continue

            if line.startswith("#fields"):
                field_names = line.split(separator)[1:]
                _check_required_fields(field_names, log_path)
                continue

            if line.startswith("#"):
                continue

            if not line.strip():
                continue

            # ── Riga dati ──────────────────────────────────────────────
            parts = line.split(separator)
            if len(parts) != len(field_names):
                logger.warning(
                    f"[X509Parser] Riga malformata "
                    f"(attesi {len(field_names)}, trovati {len(parts)}): "
                    f"{line[:80]}"
                )
                continue

            row = dict(zip(field_names, parts))
            rec = _extract_record(row)
            if rec:
                records.append(rec)

    logger.info(f"[X509Parser] Estratti {len(records)} certificati da {path.name}")
    return records


# ── Helpers interni ───────────────────────────────────────────────────────────

def _check_required_fields(fields: list[str], path: str) -> None:
    missing = REQUIRED_FIELDS - set(fields)
    if missing:
        logger.warning(
            f"[X509Parser] Campi mancanti in {path}: {missing}. "
            "Alcuni record potrebbero essere incompleti."
        )


def _optional(value: str) -> str | None:
    """Converte segnaposto Zeek ('-', '(empty)') in None."""
    return None if value in ("-", "(empty)", "") else value


def _to_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ts_to_iso(zeek_ts: str) -> str:
    """Converte timestamp UNIX (float string) in ISO 8601 UTC."""
    try:
        dt = datetime.fromtimestamp(float(zeek_ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        return zeek_ts  # restituisce grezzo se la conversione fallisce


def _parse_vector(value: str) -> list[str]:
    """
    Decodifica un campo vector[string] / vector[addr] di Zeek.
    Zeek usa la virgola come set_separator (configurabile); qui gestiamo
    sia il caso standard sia il caso in cui il separatore sia ','.
    """
    if not value or value in ("-", "(empty)"):
        return []
    # Zeek usa virgola come set_separator di default per i vettori
    return [v.strip() for v in value.split(",") if v.strip() and v.strip() != "-"]


def _compute_status(
    subject: str,
    issuer: str,
    sig_alg: str,
    key_type: str,
    key_length: int,
) -> list[str]:
    """
    Calcola la lista di stati del certificato:
        VALID / SELF_SIGNED / WEAK_SIG / WEAK_KEY

    Nota: EXPIRED non può essere calcolato qui senza accesso all'ora
    corrente e alle date not_before/not_after come oggetti datetime;
    viene calcolato separatamente in _check_expiry().
    """
    statuses: list[str] = []

    # Self-signed: subject == issuer
    if subject and issuer and subject.strip() == issuer.strip():
        statuses.append("SELF_SIGNED")

    # Weak signature algorithm
    if sig_alg and sig_alg.lower().replace(" ", "") in {
        s.replace(" ", "") for s in WEAK_SIG_ALGS
    }:
        statuses.append("WEAK_SIG")

    # Weak key
    kt = key_type.lower()
    threshold = WEAK_KEY_THRESHOLDS.get(kt)
    if threshold and 0 < key_length < threshold:
        statuses.append("WEAK_KEY")

    if not statuses:
        statuses.append("VALID")

    return statuses


def _check_expiry(not_before_iso: str, not_after_iso: str, statuses: list[str]) -> list[str]:
    """
    Aggiunge EXPIRED se il certificato è scaduto rispetto all'ora UTC corrente.
    Rimuove VALID se il certificato risulta scaduto.
    """
    try:
        now = datetime.now(timezone.utc)
        not_after_dt = datetime.strptime(not_after_iso, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        if now > not_after_dt:
            statuses = [s for s in statuses if s != "VALID"]
            if "EXPIRED" not in statuses:
                statuses.append("EXPIRED")
    except (ValueError, TypeError):
        pass  # se la data non è parsabile, non aggiungiamo EXPIRED
    return statuses


def _extract_record(row: dict) -> dict | None:
    """Mappa una riga raw di x509.log verso un CertRecord."""
    try:
        ts_raw       = row.get("ts", "0")
        fingerprint  = _optional(row.get("fingerprint", "-")) or ""
        version      = _to_int(row.get("certificate.version", "3"), default=3)
        serial       = _optional(row.get("certificate.serial", "-")) or ""
        subject      = _optional(row.get("certificate.subject", "-")) or ""
        issuer       = _optional(row.get("certificate.issuer", "-")) or ""

        not_before_raw = row.get("certificate.not_valid_before", "-")
        not_after_raw  = row.get("certificate.not_valid_after", "-")
        not_before_iso = _ts_to_iso(not_before_raw) if _optional(not_before_raw) else ""
        not_after_iso  = _ts_to_iso(not_after_raw)  if _optional(not_after_raw)  else ""

        key_alg    = _optional(row.get("certificate.key_alg",  "-")) or ""
        sig_alg    = _optional(row.get("certificate.sig_alg",  "-")) or ""
        key_type   = _optional(row.get("certificate.key_type", "-")) or ""
        key_length = _to_int(row.get("certificate.key_length", "0"))
        exponent   = _optional(row.get("certificate.exponent", "-"))
        curve      = _optional(row.get("certificate.curve",    "-"))

        san_dns   = _parse_vector(row.get("san.dns",   "-"))
        san_uri   = _parse_vector(row.get("san.uri",   "-"))
        san_email = _parse_vector(row.get("san.email", "-"))
        san_ip    = _parse_vector(row.get("san.ip",    "-"))

        is_ca_raw  = row.get("basic_constraints.ca", "-")
        is_ca      = is_ca_raw.upper() == "T" if _optional(is_ca_raw) else False
        path_len   = _to_int(row.get("basic_constraints.path_len", "-"), default=-1)
        path_len   = path_len if path_len >= 0 else None

        host_cert_raw   = row.get("host_cert",   "-")
        client_cert_raw = row.get("client_cert", "-")
        host_cert   = host_cert_raw.upper()   == "T" if _optional(host_cert_raw)   else False
        client_cert = client_cert_raw.upper() == "T" if _optional(client_cert_raw) else False

        # Calcolo status
        statuses = _compute_status(subject, issuer, sig_alg, key_type, key_length)
        statuses = _check_expiry(not_before_iso, not_after_iso, statuses)

        return {
            "ts":          float(ts_raw),
            "fingerprint": fingerprint,
            "version":     version,
            "serial":      serial,
            "subject":     subject,
            "issuer":      issuer,
            "not_before":  not_before_iso,
            "not_after":   not_after_iso,
            "key_alg":     key_alg,
            "sig_alg":     sig_alg,
            "key_type":    key_type,
            "key_length":  key_length,
            "exponent":    exponent,
            "curve":       curve,
            "san_dns":     san_dns,
            "san_uri":     san_uri,
            "san_email":   san_email,
            "san_ip":      san_ip,
            "is_ca":       is_ca,
            "path_len":    path_len,
            "host_cert":   host_cert,
            "client_cert": client_cert,
            "status":      statuses,
            # I certificati proteggono sempre l'autenticità del server
            "cia_impact":  ["AUTHENTICITY"],
        }

    except Exception as exc:
        logger.error(f"[X509Parser] Errore parsing riga: {exc} — {row}")
        return None


# ── Utility per il normalizzatore ─────────────────────────────────────────────

def build_fingerprint_index(cert_records: list[dict]) -> dict[str, dict]:
    """
    Costruisce un indice { fingerprint -> CertRecord } per la correlazione
    rapida con i cert_chain_fps di ssl.log.

    Args:
        cert_records: lista restituita da parse().

    Returns:
        Dizionario { fingerprint_hex: cert_record }.
    """
    return {r["fingerprint"]: r for r in cert_records if r.get("fingerprint")}


def build_ip_time_index(cert_records: list[dict]) -> list[dict]:
    """
    Restituisce la lista di CertRecord ordinata per timestamp, utile per
    la correlazione fallback per IP+timestamp quando cert_chain_fps non
    è disponibile in ssl.log.

    I record sono già nella lista originale; questa funzione li restituisce
    semplicemente ordinati per ts crescente.
    """
    return sorted(cert_records, key=lambda r: r.get("ts", 0.0))


def correlate_by_fingerprints(
    fps: list[str],
    fp_index: dict[str, dict],
) -> list[dict]:
    """
    Risolve una lista di fingerprint (da cert_chain_fps di ssl.log)
    nei CertRecord corrispondenti.

    Args:
        fps:      lista di fingerprint SHA-256 (hex string).
        fp_index: indice costruito da build_fingerprint_index().

    Returns:
        Lista ordinata di CertRecord (dalla foglia alla root),
        solo quelli effettivamente trovati nell'indice.
    """
    result = []
    for fp in fps:
        rec = fp_index.get(fp)
        if rec:
            result.append(rec)
        else:
            logger.debug(f"[X509Parser] Fingerprint non trovato in x509.log: {fp}")
    return result


def correlate_by_ip_time(
    server_ip: str,
    conn_ts: float,
    sorted_certs: list[dict],
    window_sec: float = 5.0,
) -> list[dict]:
    """
    Correlazione fallback: restituisce i certificati il cui timestamp
    è entro ±window_sec dal timestamp di connessione ssl.log E il cui
    san_ip o subject contiene server_ip.

    Questo copre scenari Zeek < 4 dove cert_chain_fps non è disponibile.

    Args:
        server_ip:    IP del server (id.resp_h da ssl.log).
        conn_ts:      timestamp della connessione TLS.
        sorted_certs: lista ordinata per ts (da build_ip_time_index()).
        window_sec:   finestra temporale in secondi (default 5).

    Returns:
        Lista di CertRecord candidati (ordinati per ts crescente).
    """
    candidates = []
    for rec in sorted_certs:
        cert_ts = rec.get("ts", 0.0)
        if abs(cert_ts - conn_ts) > window_sec:
            continue
        # Controlla se server_ip appare nel SAN IP o nel Subject
        if server_ip in rec.get("san_ip", []):
            candidates.append(rec)
            continue
        subj = rec.get("subject", "")
        if server_ip in subj:
            candidates.append(rec)
    return candidates
