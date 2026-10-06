# -*- coding: utf-8 -*-
"""
smtp_parser.py — reads shared/<sensor>/zeeklogs/smtp.log.

This was the concrete gap: scanner.py already discovered this file (it
was in the ZEEK_LOG_KINDS list), but no parser ever read it. The
practical result was that an SMTP/STARTTLS session ended up in the CBOM
only as "a TLS session on port 25" — indistinguishable from any TLS
session except for the port number, without the application context
(HELO, explicit confirmation that STARTTLS succeeded) that only smtp.log
carries.

The `tls` field here is Zeek's attestation, at the SMTP analyzer level,
that the session really switched to STARTTLS — a second point of view on
the same event compared with ssl.log alone, useful in correlate.py to
confirm the consistency between the two (or to flag a mismatch, should
one ever appear).
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

            records.append({
                "protocol": "SMTP",
                "sensor_id": sensor_id,
                "log_kind": "smtp",
                "uid": d.get("uid"),
                "ts": d.get("ts"),
                "src_ip": d.get("id.orig_h"),
                "src_port": d.get("id.orig_p"),
                "dst_ip": d.get("id.resp_h"),
                "dst_port": d.get("id.resp_p"),
                "helo": d.get("helo"),
                "last_reply": d.get("last_reply"),
                "starttls_confirmed": bool(d.get("tls")),
            })
    return records
