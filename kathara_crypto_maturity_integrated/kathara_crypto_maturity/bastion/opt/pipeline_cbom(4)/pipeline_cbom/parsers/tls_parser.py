# -*- coding: utf-8 -*-
"""
tls_parser.py — legge shared/<sensor>/zeeklogs/ssl.log (JSON riga per riga,
LogAscii::use_json=T) e produce record intermedi normalizzati.

Nota di osservabilità (non è un dettaglio implementativo, è centrale):
in TLS 1.3 il messaggio Certificate è cifrato — cert_chain_fps sarà
un array vuoto (o assente) per qualunque sessione TLS 1.3, non per un
difetto del parser. Il campo cert_observation_method rende esplicito
perché il certificato non è stato osservato, invece di lasciare un vuoto
ambiguo indistinguibile da un errore di raccolta.
"""
from __future__ import annotations
import json
from pathlib import Path


def parse(path: Path, sensor_id: str) -> list[dict]:
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue

            version = d.get("version")
            cert_fps = d.get("cert_chain_fps") or []
            client_cert_fps = d.get("client_cert_chain_fps") or []

            if version == "TLSv13":
                cert_method = "not_observable_tls13_encrypted_certificate"
            elif cert_fps:
                cert_method = "exact_fingerprint_match"
            else:
                cert_method = "not_observed"

            records.append({
                "protocol": "TLS",
                "sensor_id": sensor_id,
                "log_kind": "ssl",
                "uid": d.get("uid"),
                "ts": d.get("ts"),
                "src_ip": d.get("id.orig_h"),
                "src_port": d.get("id.orig_p"),
                "dst_ip": d.get("id.resp_h"),
                "dst_port": d.get("id.resp_p"),
                "tls_version": version,
                "cipher": d.get("cipher"),
                "curve": d.get("curve"),
                "resumed": d.get("resumed"),
                "established": d.get("established"),
                "cert_chain_fps": cert_fps,
                "client_cert_chain_fps": client_cert_fps,
                "cert_observation_method": cert_method,
                # PFS: TLS 1.3 porta sempre un key-share fresco in un handshake
                # completo (non ripreso); un handshake "resumed" senza curva è
                # PSK-only, quindi senza un nuovo scambio DH.
                "has_pfs": (
                    None if version != "TLSv13"
                    else not (d.get("resumed") and not d.get("curve"))
                ),
            })
    return records
