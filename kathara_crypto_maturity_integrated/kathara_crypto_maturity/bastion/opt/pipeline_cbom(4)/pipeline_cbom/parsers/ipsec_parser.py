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
                records.append(current)
            current = {
                "protocol": "IPSEC_IKE",
                "sensor_id": sensor_id,
                "conn_name": m.group("name"),
                "ike_uid": m.group("uid"),
                "state": m.group("state"),
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
        records.append(current)

    return records
