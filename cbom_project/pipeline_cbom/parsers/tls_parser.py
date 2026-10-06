# -*- coding: utf-8 -*-
"""
tls_parser.py — reads shared/<sensor>/zeeklogs/ssl.log (JSON line by
line, LogAscii::use_json=T) and produces normalized intermediate records.

Observability note (not an implementation detail, it is central): in
TLS 1.3 the Certificate message is encrypted — cert_chain_fps will be an
empty (or missing) array for any TLS 1.3 session, not because of a
parser defect. The cert_observation_method field makes explicit why the
certificate was not observed, instead of leaving an ambiguous gap
indistinguishable from a collection error.
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
                # PFS: TLS 1.3 always carries a fresh key share in a full
                # (non-resumed) handshake; a "resumed" handshake without a
                # curve is PSK-only, hence without a new DH exchange.
                "has_pfs": (
                    None if version != "TLSv13"
                    else not (d.get("resumed") and not d.get("curve"))
                ),
            })
    return records
