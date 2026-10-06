"""
ipsec_loader.py — Fase EXTRACT/TRANSFORM per gli asset crittografici IPSec
═══════════════════════════════════════════════════════════════════════════

REVISIONE 2 — correzione formato sorgente
───────────────────────────────────────────────────────────────────────────
La revisione precedente assumeva che /shared/ipsec_crypto_telemetry.json
contenesse JSON strutturato. In realtà il file, nonostante l'estensione
".json", contiene l'output testuale grezzo del comando CLI

    swanctl --list-sas

eseguito automaticamente su remote_router (nessuna conversione a JSON a
monte). Questo modulo fa quindi parsing di testo, non json.load().
Il nome del file resta ipsec_crypto_telemetry.json per compatibilità con
lo script di raccolta già in uso su remote_router; è un'etichetta, non
un vincolo di formato.

REVISIONE 1 — cambio di sorgente e modello di osservazione (invariata)
───────────────────────────────────────────────────────────────────────────
Limite epistemico del modello precedente (ike_cbom.json, deprecato):
    IKE_SA_INIT è in chiaro e osservabile passivamente, ma IKE_AUTH —
    che negozia la Child SA, cioè gli algoritmi ESP del piano dati —
    avviene già dentro il canale cifrato dalla IKE SA. Un osservatore
    passivo di rete non può quindi ricavare gli algoritmi ESP: assumerli
    identici a quelli IKE (comportamento del loader precedente) è
    un'inferenza, non un dato osservato.

Nuovo modello:
    La sorgente diventa una raccolta ATTIVA a bordo dell'endpoint
    remote_router: interrogazione automatizzata di `swanctl --list-sas`
    (interfaccia VICI di strongSwan), che ha visibilità diretta sia sulla
    IKE SA sia su ogni Child SA effettivamente installata. IKE e ESP sono
    quindi modellati come entità distinte (vedi normalizer.normalize_ipsec),
    ciascuna con la propria origine osservativa dichiarata.

── Formato atteso di /shared/ipsec_crypto_telemetry.json (testo, non JSON) ──

Esempio reale (output di `swanctl --list-sas`):

    site-to-site: #2, ESTABLISHED, IKEv2, 9eebf654a92230a6_i 03b784a3bfdee413_r*
      local  'CN=gwB' @ 10.0.5.2[4500]
      remote 'CN=gwA' @ 10.0.1.254[4500]
      AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
      established 2s ago, reauth in 9801s
      site-to-site: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
        installed 2s ago, rekeying in 2688s, expires in 3598s
        in  c9dc209a,      0 bytes,     0 packets
        out cd3f0b52,      0 bytes,     0 packets
        local  10.0.4.0/24
        remote 10.0.0.0/24

Struttura riconosciuta per indentazione (2 spazi per livello, coerente
con l'output reale di swanctl):

  livello 0 (nessun indent) — intestazione IKE SA:
      "<nome>: #<uid>, <STATE>, IKEv<n>, <spi_i>_i <spi_r>_r[*]"

  livello 1 (2 spazi) — attributi della IKE SA:
      "local  '<id>' @ <host>[<porta>]"
      "remote '<id>' @ <host>[<porta>]"
      "<ENC>[-<keysize>]/<INTEG>/<PRF>/<DH>"   (riga della cipher suite,
          nessuna parola chiave: riconosciuta per pattern token/token/...)
      "established ... / rekeying ..."          (ignorata ai fini crypto)
    oppure, allo stesso livello, l'intestazione di una Child SA:
      "<nome>: #<uid>, reqid <n>, <STATE>, <MODE>, ESP|AH:<ENC>[/<INTEG>][/<DH>]"

  livello 2 (4 spazi) — attributi della Child SA:
      "installed ... / rekeying ... / expires ..."  (ignorata)
      "in  <spi>, <bytes> bytes, <packets> packets"  (ignorata)
      "out <spi>, <bytes> bytes, <packets> packets"  (ignorata)
      "local  <traffic-selector>[, <ts>...]"
      "remote <traffic-selector>[, <ts>...]"

Nota sui nomi delle primitive:
  Lo swanctl reale usa il trattino nel campo cipher+keysize (es.
  "AES_CBC-256"). Il parser normalizza tutto sostituendo "-" con "_"
  per allinearsi alla nomenclatura canonica IANA/IKEv2 già usata dagli
  evaluator del normalizer (es. "AES_CBC_256", "AES_GCM_16").

Nota su sig_hashes / host_key_alg:
  `swanctl --list-sas` non espone l'algoritmo di firma usato in IKE_AUTH
  per l'autenticazione degli endpoint. Il campo sig_hashes viene quindi
  sempre prodotto come lista vuota: gap di visibilità distinto, tracciato
  separatamente (allineamento della dimensione HOSTKEY), non affrontato
  da questo modulo.

Schema del record intermedio prodotto (input per normalizer.normalize_ipsec):
  invariato rispetto alla Revisione 1 — vedi normalize_ipsec/_normalize_ike_sa/
  _normalize_child_sa in normalizer.py. Un record plane="IKE" per IKE SA,
  un record plane="ESP" per ciascuna Child SA (o un segnaposto con
  observed=False se la IKE SA non ha Child SA installate).
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

OBSERVATION_METHOD = "active_endpoint_query"

# ── Pattern noti per il riconoscimento delle famiglie di token ─────────────
_DH_PREFIXES = ("MODP_", "ECP_", "CURVE_", "NTRU", "KYBER", "ML_KEM",
                "FRODO", "SNTRUP", "BRAINPOOL")

_IKE_HEADER_RE = re.compile(
    r"^(?P<name>[^:]+):\s*#(?P<uid>\d+),\s*(?P<state>[A-Za-z_]+),\s*"
    r"(?P<version>IKEv\d)\b"
)
_CHILD_HEADER_RE = re.compile(
    r"^(?P<name>[^:]+):\s*#(?P<uid>\d+),\s*reqid\s+\d+,\s*"
    r"(?P<state>[A-Za-z_]+),\s*(?P<mode>[A-Za-z_]+),\s*"
    r"(?P<proto>ESP|AH):(?P<suite>\S+)"
)
_ID_HOST_RE = re.compile(
    r"^(?P<role>local|remote)\s+(?:'(?P<id>[^']*)'\s*)?@\s*"
    r"(?P<host>[^\[\s]+)(?:\[(?P<port>\d+)\])?"
)
_TS_RE = re.compile(r"^(?P<role>local|remote)\s+(?P<ts>.+)$")
_SUITE_LINE_RE = re.compile(r"^[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-]+){1,4}$")
_SKIP_PREFIXES = ("established", "rekeying", "reauth", "installed", "in ", "out ", "expires")


def parse(path_str: str) -> list[dict]:
    """
    Legge /shared/ipsec_crypto_telemetry.json — testo grezzo prodotto da
    `swanctl --list-sas` su remote_router, NON JSON — e restituisce una
    lista di record intermedi compatibili con normalizer.normalize_ipsec().

    Raises:
        FileNotFoundError: se il file non esiste.
        ValueError: se dal testo non si riesce a estrarre nessuna IKE SA.
    """
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"[IPSecLoader] File non trovato: {path_str}")

    logger.info(f"[IPSecLoader] Lettura (testo swanctl --list-sas): {path}")
    text = path.read_text(encoding="utf-8", errors="replace")

    ike_sas = _parse_swanctl_text(text)

    if not ike_sas:
        raise ValueError(
            f"[IPSecLoader] Nessuna IKE SA riconosciuta in {path_str}. "
            "Verificare che il file contenga l'output testuale integrale "
            "di 'swanctl --list-sas' (non JSON, non vuoto)."
        )

    generated_at = datetime.now(timezone.utc).isoformat()
    ts = _iso_to_unix(generated_at)
    source_file = str(path)

    records: list[dict] = []
    for ike_sa in ike_sas:
        records.append(_build_ike_record(ike_sa, ts, generated_at, source_file))

        child_sas = ike_sa.get("child_sas") or []
        if not child_sas:
            records.append(_placeholder_esp_record(ike_sa, ts, generated_at, source_file))
            continue
        for child_sa in child_sas:
            records.append(_build_esp_record(ike_sa, child_sa, ts, generated_at, source_file))

    n_ike = sum(1 for r in records if r["plane"] == "IKE")
    n_esp = sum(1 for r in records if r["plane"] == "ESP")
    n_esp_unobserved = sum(1 for r in records if r["plane"] == "ESP" and not r["observed"])
    logger.info(
        f"[IPSecLoader] Estratti {n_ike} IKE SA e {n_esp} Child SA "
        f"({n_esp_unobserved} non osservate) da {path.name}"
    )
    return records


# ── Parser testuale ─────────────────────────────────────────────────────

def _parse_swanctl_text(text: str) -> list[dict]:
    """
    Parsing riga per riga dell'output di `swanctl --list-sas`, con
    livello di indentazione (0/2/4 spazi) a discriminare IKE SA / suoi
    attributi (o header Child SA) / attributi della Child SA.
    """
    ike_sas: list[dict] = []
    current_ike: dict | None = None
    current_child: dict | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        # ── livello 0: nuova IKE SA ────────────────────────────────────
        if indent == 0:
            m = _IKE_HEADER_RE.match(line)
            if not m:
                logger.debug(f"[IPSecLoader] Riga di livello 0 non riconosciuta, ignorata: {line!r}")
                continue
            current_ike = {
                "name":        m.group("name").strip(),
                "uid":         m.group("uid"),
                "state":       m.group("state"),
                "version":     m.group("version"),
                "local_host":  None, "local_port": 500,
                "remote_host": None, "remote_port": 500,
                "enc": None, "integ": None, "prf": None, "dh": None,
                "child_sas": [],
            }
            current_child = None
            ike_sas.append(current_ike)
            continue

        if current_ike is None:
            logger.debug(f"[IPSecLoader] Riga indentata prima di qualunque IKE SA, ignorata: {line!r}")
            continue

        # ── livello 1 (2 spazi): attributi IKE SA o header Child SA ───
        if indent == 2:
            m_child = _CHILD_HEADER_RE.match(line)
            if m_child:
                enc, integ, dh = _split_suite(m_child.group("suite"))
                current_child = {
                    "name":  m_child.group("name").strip(),
                    "uid":   m_child.group("uid"),
                    "state": m_child.group("state"),
                    "mode":  m_child.group("mode"),
                    "proto": m_child.group("proto"),
                    "enc": enc, "integ": integ, "dh": dh,
                    "local_ts": [], "remote_ts": [],
                }
                current_ike["child_sas"].append(current_child)
                continue

            m_id = _ID_HOST_RE.match(line)
            if m_id:
                role = m_id.group("role")
                current_ike[f"{role}_host"] = m_id.group("host")
                if m_id.group("port"):
                    current_ike[f"{role}_port"] = int(m_id.group("port"))
                current_child = None
                continue

            if _SUITE_LINE_RE.match(line):
                enc, integ, dh, prf = _split_ike_suite(line)
                current_ike["enc"], current_ike["integ"] = enc, integ
                current_ike["dh"], current_ike["prf"] = dh, prf
                current_child = None
                continue

            if line.startswith(_SKIP_PREFIXES):
                continue

            logger.debug(f"[IPSecLoader] Riga di livello 1 non riconosciuta, ignorata: {line!r}")
            continue

        # ── livello 2+ (>=4 spazi): attributi Child SA ─────────────────
        if current_child is None:
            # es. righe di dettaglio di una IKE SA senza Child SA associata,
            # o indentazioni anomale: ignorate senza propagare dati errati.
            continue

        if line.startswith(_SKIP_PREFIXES):
            continue

        m_ts = _TS_RE.match(line)
        if m_ts:
            role = m_ts.group("role")
            selectors = [s.strip() for s in m_ts.group("ts").split(",") if s.strip()]
            current_child[f"{role}_ts"] = selectors
            continue

        logger.debug(f"[IPSecLoader] Riga di livello 2 non riconosciuta, ignorata: {line!r}")

    return ike_sas


def _split_suite(suite: str) -> tuple[str | None, str | None, str | None]:
    """
    Spezza una cipher suite Child SA (es. "AES_CBC-256/HMAC_SHA2_256_128"
    o "AES_GCM_16" o "AES_GCM_16/MODP_2048" per PFS esplicito) in
    (encryption, auth, dh_group). Normalizza '-' in '_'.
    """
    tokens = [t.replace("-", "_") for t in suite.split("/") if t]
    enc = integ = dh = None
    remaining = []
    for tok in tokens:
        if tok.upper().startswith(_DH_PREFIXES):
            dh = tok
        else:
            remaining.append(tok)
    if remaining:
        enc = remaining[0]
    if len(remaining) > 1:
        integ = remaining[1]
    return enc, integ, dh


def _split_ike_suite(line: str) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Spezza la riga di cipher suite di una IKE SA (es.
    "AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048") in
    (encryption, auth, dh_group, prf). Normalizza '-' in '_'.
    """
    tokens = [t.replace("-", "_") for t in line.split("/") if t]
    enc = integ = dh = prf = None
    remaining = []
    for tok in tokens:
        tu = tok.upper()
        if tu.startswith("PRF_"):
            prf = tok
        elif tu.startswith(_DH_PREFIXES):
            dh = tok
        else:
            remaining.append(tok)
    if remaining:
        enc = remaining[0]
    if len(remaining) > 1:
        integ = remaining[1]
    return enc, integ, dh, prf


# ── Costruzione dei record intermedi ────────────────────────────────────

def _build_ike_record(ike_sa: dict, ts: float, generated_at: str, source_file: str) -> dict:
    return {
        "uid":                f"ipsec-ike-{ike_sa['uid']}",
        "plane":              "IKE",
        "ike_sa_uid":         ike_sa["uid"],
        "ike_sa_name":        ike_sa["name"],
        "ike_sa_state":       ike_sa.get("state", "UNKNOWN"),
        "ts":                 ts,
        "src_ip":             ike_sa.get("local_host") or "unknown",
        "src_port":           ike_sa.get("local_port", 500),
        "dst_ip":             ike_sa.get("remote_host") or "unknown",
        "dst_port":           ike_sa.get("remote_port", 500),
        "proto_version":      ike_sa.get("version", "IKEv2"),
        "observation_method": OBSERVATION_METHOD,
        "observed":           True,
        "ike": {
            "encryption": ike_sa.get("enc"),
            "auth":       ike_sa.get("integ"),
            "prf":        ike_sa.get("prf"),
            "dh_group":   ike_sa.get("dh"),
        },
        "sig_hashes":   [],  # non esposto da swanctl --list-sas (vedi docstring)
        "source_file":  source_file,
        "generated_at": generated_at,
    }


def _build_esp_record(ike_sa: dict, child_sa: dict, ts: float, generated_at: str, source_file: str) -> dict:
    state = child_sa.get("state", "UNKNOWN")
    return {
        "uid":                f"ipsec-esp-{ike_sa['uid']}-{child_sa['uid']}",
        "plane":              "ESP",
        "ike_sa_uid":         ike_sa["uid"],
        "ike_sa_name":        ike_sa["name"],
        "ts":                 ts,
        "src_ip":             ike_sa.get("local_host") or "unknown",
        "src_port":           ike_sa.get("local_port", 500),
        "dst_ip":             ike_sa.get("remote_host") or "unknown",
        "dst_port":           ike_sa.get("remote_port", 500),
        "proto_version":      ike_sa.get("version", "IKEv2"),
        "observation_method": OBSERVATION_METHOD,
        "observed":           state.upper() == "INSTALLED",
        "esp": {
            "encryption": child_sa.get("enc"),
            "auth":       child_sa.get("integ"),
            "dh_group":   child_sa.get("dh"),
        },
        "child_sa_name":  child_sa.get("name"),
        "child_sa_state": state,
        "mode":           child_sa.get("mode", "TUNNEL"),
        "local_ts":       child_sa.get("local_ts", []),
        "remote_ts":      child_sa.get("remote_ts", []),
        "source_file":    source_file,
        "generated_at":   generated_at,
    }


def _placeholder_esp_record(ike_sa: dict, ts: float, generated_at: str, source_file: str) -> dict:
    """
    Nessuna Child SA installata per questa IKE SA al momento della query:
    il piano dati resta non osservato anche con raccolta attiva. Dichiarato
    esplicitamente, non assunto uguale al piano di controllo.
    """
    return {
        "uid":                f"ipsec-esp-{ike_sa['uid']}-none",
        "plane":              "ESP",
        "ike_sa_uid":         ike_sa["uid"],
        "ike_sa_name":        ike_sa["name"],
        "ts":                 ts,
        "src_ip":             ike_sa.get("local_host") or "unknown",
        "src_port":           ike_sa.get("local_port", 500),
        "dst_ip":             ike_sa.get("remote_host") or "unknown",
        "dst_port":           ike_sa.get("remote_port", 500),
        "proto_version":      ike_sa.get("version", "IKEv2"),
        "observation_method": OBSERVATION_METHOD,
        "observed":           False,
        "esp":                None,
        "child_sa_name":      None,
        "child_sa_state":     "NOT_OBSERVED",
        "mode":               None,
        "local_ts":           [],
        "remote_ts":          [],
        "source_file":        source_file,
        "generated_at":       generated_at,
    }


def _iso_to_unix(iso_str: str) -> float:
    if not iso_str:
        return 0.0
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0
