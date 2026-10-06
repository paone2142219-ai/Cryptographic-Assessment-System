# -*- coding: utf-8 -*-
"""ssh_parser.py — reads shared/<sensor>/zeeklogs/ssh.log."""
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
                "protocol": "SSH",
                "sensor_id": sensor_id,
                "log_kind": "ssh",
                "uid": d.get("uid"),
                "ts": d.get("ts"),
                "src_ip": d.get("id.orig_h"),
                "src_port": d.get("id.orig_p"),
                "dst_ip": d.get("id.resp_h"),
                "dst_port": d.get("id.resp_p"),
                "ssh_version": d.get("version"),
                "client_banner": d.get("client"),
                "server_banner": d.get("server"),
                "kex_alg": d.get("kex_alg"),
                "host_key_alg": d.get("host_key_alg"),
                "host_key_fingerprint": d.get("host_key_fingerprint"),
                "cipher_alg": d.get("cipher_alg"),
                "mac_alg": d.get("mac_alg"),
                "compression_alg": d.get("compression_alg"),
                "auth_success": d.get("auth_success"),
                "auth_attempts": d.get("auth_attempts"),
            })
    return records
