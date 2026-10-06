# -*- coding: utf-8 -*-
"""
ipsec_parser.py — legge shared/<sensor>/ipsec_status.txt: testo grezzo
prodotto da `swanctl --list-sas` (non JSON, nonostante venga scritto da
un collector attivo — vedi vici_collector.sh).

Regex validate contro output reale di un demone charon in esecuzione e
contro esempi indipendenti (non auto-prodotti) durante lo sviluppo del
laboratorio — vedi le sessioni precedenti per il dettaglio della verifica.

Distinzione IKE/ESP: la Child SA (piano dati) porta un gruppo DH solo se
il rekey lo ha effettivamente incluso nella proposta — la primissima
Child SA negoziata dentro IKE_AUTH non lo porta mai per costruzione del
protocollo IKEv2, indipendentemente da come è configurata la proposta.
has_pfs riflette quindi ciò che è stato osservato in QUESTO campionamento,
non ciò che la configurazione permetterebbe in astratto.
"""
from __future__ import annotations
import re
from pathlib import Path

_IKE_HEADER_RE = re.compile(
    r"^(?P<name>[\w.\-]+):\s+#(?P<uid>\d+),\s+(?P<state>[A-Z]+),\s+IKEv2"
)
_LOCAL_RE = re.compile(r"^\s*local\s+'(?P<id>[^']+)'\s+@\s+(?P<addr>[0-9.]+)\[")
_REMOTE_RE = re.compile(r"^\s*remote\s+'(?P<id>[^']+)'\s+@\s+(?P<addr>[0-9.]+)\[")
_IKE_PROPOSAL_RE = re.compile(
    r"^\s*(?P<enc>[A-Z0-9_]+)-(?P<enc_bits>\d+)/PRF_(?P<prf>[A-Z0-9_]+)/(?P<group>[A-Z0-9_]+)\s*$"
)
_CHILD_HEADER_RE = re.compile(
    r"^\s*(?P<name>[\w.\-]+):\s+#(?P<cuid>\d+),\s+reqid\s+\d+,\s+(?P<state>[A-Z]+),\s+"
    r"TUNNEL,\s+ESP:(?P<enc>[A-Z0-9_]+)-(?P<enc_bits>\d+)(?:/(?P<group>[A-Z0-9_]+))?"
)

# ── swanctl --list-conns: metadata di CONFIGURAZIONE, non di stato ────────
# Fonte diversa da --list-sas: qui vive il metodo di autenticazione e il
# rekey time configurato, mai osservabili nell'output delle SA attive.
# Non contiene mai il segreto PSK stesso (swanctl non lo espone, qui né
# altrove) — solo che l'autenticazione è "pre-shared key", non il valore.
_CONN_HEADER_RE = re.compile(
    r"^(?P<name>[\w.\-]+):\s+IKEv\d,\s+(?P<reauth>[^,]+),\s+rekeying every (?P<rekey>\d+)s"
)
_AUTH_LINE_RE = re.compile(
    r"^\s*(?P<side>local|remote)\s+(?P<method>pre-shared key|public key|EAP[\w_]*)\s+authentication:"
)
_CHILD_CONN_RE = re.compile(
    r"^\s*(?P<name>[\w.\-]+):\s+TUNNEL,\s+rekeying every (?P<rekey>\d+)s"
)

_AUTH_METHOD_MAP = {
    "pre-shared key": "psk",
    "public key": "pubkey",
}


def parse_conns(path: Path, sensor_id: str) -> dict[str, dict]:
    """Legge l'output di `swanctl --list-conns` (testo grezzo, stesso
    principio di --list-sas). Restituisce {nome_connessione: metadata},
    indicizzato per nome — è pensato per essere correlato con i record
    prodotti da parse(), non per essere usato da solo."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return {}

    conns: dict[str, dict] = {}
    current_name: str | None = None
    pending_side: str | None = None

    for line in text.splitlines():
        m = _CONN_HEADER_RE.match(line)
        if m:
            current_name = m.group("name")
            conns[current_name] = {
                "conn_name": current_name,
                "sensor_id": sensor_id,
                "reauthentication": m.group("reauth").strip(),
                "ike_rekey_time_seconds": int(m.group("rekey")),
                "local_auth_method": None,
                "remote_auth_method": None,
                "child_rekey_time_seconds": None,
            }
            pending_side = None
            continue
        if current_name is None:
            continue

        m = _AUTH_LINE_RE.match(line)
        if m:
            method = _AUTH_METHOD_MAP.get(m.group("method"), m.group("method").lower())
            conns[current_name][f'{m.group("side")}_auth_method'] = method
            continue

        m = _CHILD_CONN_RE.match(line)
        if m:
            conns[current_name]["child_rekey_time_seconds"] = int(m.group("rekey"))
            continue

    return conns


def merge_conn_metadata(sa_records: list[dict], conn_metadata: dict[str, dict]) -> int:
    """Arricchisce in-place i record IKE (da --list-sas) con i metadati di
    configurazione trovati in --list-conns per lo stesso nome di
    connessione. Non tutte le SA hanno una connessione corrispondente nel
    campionamento --list-conns dello stesso sensore (es. sensori diversi
    che raccolgono in momenti diversi) — in quel caso i campi restano
    espliciti a None, mai indovinati. Restituisce il numero di record
    arricchiti."""
    merged = 0
    for rec in sa_records:
        meta = conn_metadata.get(rec.get("conn_name"))
        rec["auth_method"] = {
            "local": meta["local_auth_method"] if meta else None,
            "remote": meta["remote_auth_method"] if meta else None,
        }
        rec["ike_rekey_time_seconds"] = meta["ike_rekey_time_seconds"] if meta else None
        rec["child_rekey_time_seconds"] = meta["child_rekey_time_seconds"] if meta else None
        if meta:
            merged += 1
    return merged


def _finalize(rec: dict) -> dict:
    """Calcola data_plane_pfs_observed a chiusura di un blocco IKE, una
    volta note tutte le sue Child SA. Tre esiti possibili, mai appiattiti
    a un booleano che nasconderebbe il terzo caso:
      - True  : almeno una Child SA ha PFS osservata in questo campione
      - False : ci sono Child SA, nessuna con PFS osservata ora
      - None  : nessuna Child SA nota per questa IKE SA in questo campione
                (non "PFS assente", proprio "non so, non c'è dato")"""
    child_sas = rec.get("child_sas") or []
    if not child_sas:
        rec["data_plane_pfs_observed"] = None
    else:
        rec["data_plane_pfs_observed"] = any(c.get("has_pfs") for c in child_sas)
    return rec


def parse(path: Path, sensor_id: str) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return []

    lines = text.splitlines()
    records: list[dict] = []
    current: dict | None = None

    for line in lines:
        m = _IKE_HEADER_RE.match(line)
        if m:
            if current:
                records.append(_finalize(current))
            current = {
                "protocol": "IPSEC_IKE",
                "sensor_id": sensor_id,
                "conn_name": m.group("name"),
                "ike_uid": m.group("uid"),
                "state": m.group("state"),
                # Segnaposto: valorizzati più tardi da merge_conn_metadata(),
                # ma dichiarati qui perché la LORO POSIZIONE nel JSON sia
                # accanto all'identità della connessione, non in coda al
                # dizionario (dove finirebbe una chiave aggiunta dopo).
                "auth_method": {"local": None, "remote": None},
                "ike_rekey_time_seconds": None,
                "child_rekey_time_seconds": None,
                # Sintesi di leggibilità: "è stata osservata PFS su almeno
                # una Child SA di questa IKE SA in QUESTO campionamento?" —
                # calcolato a fine parsing, non dedotto dalla config. Il
                # dettaglio completo, per Child SA, resta comunque in
                # child_sas[].has_pfs — questo è solo la vista rapida.
                "data_plane_pfs_observed": None,
                "local_id": None, "local_addr": None,
                "remote_id": None, "remote_addr": None,
                "ike_enc": None, "ike_enc_bits": None,
                "ike_prf": None, "ike_group": None,
                "child_sas": [],
            }
            continue
        if current is None:
            continue

        m = _LOCAL_RE.match(line)
        if m:
            current["local_id"] = m.group("id")
            current["local_addr"] = m.group("addr")
            continue

        m = _REMOTE_RE.match(line)
        if m:
            current["remote_id"] = m.group("id")
            current["remote_addr"] = m.group("addr")
            continue

        m = _IKE_PROPOSAL_RE.match(line)
        if m:
            current["ike_enc"] = m.group("enc")
            current["ike_enc_bits"] = int(m.group("enc_bits"))
            current["ike_prf"] = m.group("prf")
            current["ike_group"] = m.group("group")
            continue

        m = _CHILD_HEADER_RE.match(line)
        if m:
            group = m.group("group")
            current["child_sas"].append({
                "protocol": "IPSEC_ESP",
                "child_name": m.group("name"),
                "child_uid": m.group("cuid"),
                "state": m.group("state"),
                "esp_enc": m.group("enc"),
                "esp_enc_bits": int(m.group("enc_bits")),
                "esp_group": group,
                # has_pfs=True SOLO se questo specifico campionamento ha
                # osservato un gruppo DH nella Child SA — non un'inferenza
                # dalla configurazione.
                "has_pfs": group is not None,
            })
            continue

    if current:
        records.append(_finalize(current))

    return records


# ── swanctl_config.txt: configurazione STATICA dichiarata ─────────────────
# Terza fonte, diversa dalle prime due: non interroga VICI, è una copia
# grezza dei file /etc/swanctl/conf.d/*.conf così come sono scritti.
# Qui vive la proposta ESP/IKE completa così come dichiarata (es.
# "aes256gcm16-ecp384"), mai visibile né in --list-sas né in --list-conns —
# necessaria per rendere esplicito il confronto dichiarato/osservato sulla
# PFS, invece di lasciarlo implicito e richiedere di saperlo a memoria.
_BLOCK_OPEN_RE = re.compile(r"^\s*([\w.\-]+)\s*\{\s*(?:#.*)?$")
_BLOCK_CLOSE_RE = re.compile(r"^\s*\}\s*$")
_IKE_PROPOSALS_LINE_RE = re.compile(r"^\s*proposals\s*=\s*(\S+)")
_ESP_PROPOSALS_LINE_RE = re.compile(r"^\s*esp_proposals\s*=\s*(\S+)")

# Normalizza il token DH/curva della sintassi swanctl.conf (minuscola,
# es. "ecp384") alla stessa forma usata dal resto del parser/normalizzatore
# (maiuscola, es. "ECP_384", quella che compare in --list-sas) — stessa
# entità, due sintassi diverse a seconda della fonte.
_DH_TOKEN_NORMALIZE = {
    "ecp256": "ECP_256", "ecp384": "ECP_384", "ecp521": "ECP_521",
    "curve25519": "X25519", "x25519": "X25519",
    "modp1024": "MODP_1024", "modp1536": "MODP_1536",
    "modp2048": "MODP_2048", "modp3072": "MODP_3072", "modp4096": "MODP_4096",
}


def _declared_dh_group(proposal_str: str) -> str | None:
    """Estrae il gruppo DH/curva da una stringa di proposta swanctl.conf
    (es. 'aes256gcm16-ecp384' -> 'ECP_384'). Restituisce None se nessun
    componente della proposta corrisponde a un gruppo noto — es. una
    proposta come 'aes256gcm16' da sola, senza alcun gruppo DH indicato,
    il che è essa stessa un'informazione (nessuna PFS possibile su
    quella Child SA, per qualunque rekey)."""
    for token in proposal_str.lower().split("-"):
        if token in _DH_TOKEN_NORMALIZE:
            return _DH_TOKEN_NORMALIZE[token]
    return None


def parse_static_config(path: Path, sensor_id: str) -> dict[str, dict]:
    """Legge la copia grezza di /etc/swanctl/conf.d/*.conf e restituisce
    {nome_connessione: {"declared_ike_proposal":..., "children": {nome_figlio: {...}}}}.

    Parser a stack sulla struttura a blocchi annidati di swanctl.conf —
    non un parser generico del formato (che ammette molta più sintassi di
    quella che il laboratorio usa), solo quanto serve per estrarre
    connections{name{...children{name{...esp_proposals=...}}}}."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return {}

    stack: list[str] = []
    result: dict[str, dict] = {}

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0]  # commenti a riga intera o in coda
        if not line.strip():
            continue

        m = _BLOCK_CLOSE_RE.match(line)
        if m:
            if stack:
                stack.pop()
            continue

        m = _BLOCK_OPEN_RE.match(line)
        if m:
            stack.append(m.group(1))
            continue

        # connections { <conn_name> { proposals = ... } }
        if len(stack) == 2 and stack[0] == "connections":
            m = _IKE_PROPOSALS_LINE_RE.match(line)
            if m:
                conn_name = stack[1]
                result.setdefault(conn_name, {"declared_ike_proposal": None, "children": {}})
                result[conn_name]["declared_ike_proposal"] = m.group(1)
            continue

        # connections { <conn_name> { children { <child_name> { esp_proposals = ... } } } }
        if len(stack) == 4 and stack[0] == "connections" and stack[2] == "children":
            m = _ESP_PROPOSALS_LINE_RE.match(line)
            if m:
                conn_name, child_name = stack[1], stack[3]
                result.setdefault(conn_name, {"declared_ike_proposal": None, "children": {}})
                result[conn_name]["children"].setdefault(child_name, {})
                result[conn_name]["children"][child_name]["declared_esp_proposal"] = m.group(1)

    return result


def merge_static_config(sa_records: list[dict], static_config: dict[str, dict]) -> int:
    """Arricchisce in-place i record IKE (e le loro Child SA) con la
    proposta dichiarata in configurazione statica. Come per
    merge_conn_metadata: se non c'è corrispondenza, i campi restano
    espliciti a None, mai indovinati. Restituisce il numero di record
    IKE arricchiti (non conta le singole Child SA)."""
    merged = 0
    for rec in sa_records:
        conf = static_config.get(rec.get("conn_name"))
        rec["declared_ike_proposal"] = conf["declared_ike_proposal"] if conf else None

        for child in rec.get("child_sas", []):
            child_conf = (conf or {}).get("children", {}).get(child.get("child_name"))
            declared = child_conf["declared_esp_proposal"] if child_conf else None
            child["declared_esp_proposal"] = declared
            child["declared_dh_group"] = _declared_dh_group(declared) if declared else None
            # Esplicitamente distinto da has_pfs (osservato): questo dice
            # se la CONFIGURAZIONE permetterebbe PFS a un rekey, non se
            # è mai stata osservata. I due campi vanno letti insieme, mai
            # l'uno al posto dell'altro.
            child["declared_pfs_capable"] = child["declared_dh_group"] is not None

        if conf:
            merged += 1
    return merged
