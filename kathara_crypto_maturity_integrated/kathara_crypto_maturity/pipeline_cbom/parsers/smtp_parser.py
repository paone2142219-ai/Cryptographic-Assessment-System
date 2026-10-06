# -*- coding: utf-8 -*-
"""
smtp_parser.py — legge shared/<sensor>/zeeklogs/smtp.log.

Era il gap concreto: scanner.py scopriva già questo file (era nell'elenco
ZEEK_LOG_KINDS), ma nessun parser lo leggeva mai. Il risultato pratico era
che una sessione SMTP/STARTTLS finiva nella CBOM solo come "una sessione
TLS sulla porta 25" — indistinguibile da un TLS qualunque se non per il
numero di porta, senza il contesto applicativo (HELO, conferma esplicita
di STARTTLS riuscito) che solo smtp.log porta.

Il campo `tls` qui è l'attestazione di Zeek, a livello di analizzatore
SMTP, che la sessione è realmente passata a STARTTLS — un secondo punto
di vista sullo stesso evento rispetto al solo ssl.log, utile in
correlate.py per confermare la coerenza tra i due (o segnalare un
disallineamento, se mai comparisse).
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
