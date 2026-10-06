# -*- coding: utf-8 -*-
"""x509_parser.py — legge shared/<sensor>/zeeklogs/x509.log.

Indicizzato per fingerprint: è la chiave con cui correlate.py lo aggancia
ai record TLS che riportano lo stesso fingerprint in cert_chain_fps.
"""
from __future__ import annotations
import json
from pathlib import Path


def parse(path: Path, sensor_id: str) -> dict[str, dict]:
    """Restituisce {fingerprint: record}, non una lista — un certificato
    con lo stesso fingerprint osservato da sensori diversi è lo stesso
    certificato, non un evento distinto da contare due volte."""
    certs: dict[str, dict] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue

            fp = d.get("fingerprint")
            if not fp:
                continue

            certs[fp] = {
                "fingerprint": fp,
                "subject": d.get("certificate.subject"),
                "issuer": d.get("certificate.issuer"),
                "not_valid_before": d.get("certificate.not_valid_before"),
                "not_valid_after": d.get("certificate.not_valid_after"),
                "key_alg": d.get("certificate.key_alg"),
                "sig_alg": d.get("certificate.sig_alg"),
                "key_type": d.get("certificate.key_type"),
                "key_length": d.get("certificate.key_length"),
                "curve": d.get("certificate.curve"),
                "san_dns": d.get("san.dns") or [],
                "san_ip": d.get("san.ip") or [],
                "host_cert": d.get("host_cert"),
                "client_cert": d.get("client_cert"),
                "observed_by": [sensor_id],
            }
    return certs


def merge_cert_indexes(indexes: list[dict[str, dict]]) -> dict[str, dict]:
    """Fonde più indici {fingerprint: record} provenienti da sensori
    diversi. Stesso fingerprint = stesso certificato: si fonde la lista
    observed_by invece di tenere due copie identiche."""
    merged: dict[str, dict] = {}
    for idx in indexes:
        for fp, rec in idx.items():
            if fp not in merged:
                merged[fp] = rec
            else:
                existing_hosts = set(merged[fp]["observed_by"])
                existing_hosts.update(rec["observed_by"])
                merged[fp]["observed_by"] = sorted(existing_hosts)
    return merged
