# -*- coding: utf-8 -*-
"""
asset_inventory.py — IP -> hostname map, to make the CBOM readable
without doing what the pipeline must not do.

Deliberate boundary, not to be moved in the future without justifying it
again: this module assigns a NAME to an address ("10.1.0.10 is apigw"),
not an application ROLE nor a USE CASE ("this connection is the API
Gateway use case"). They are epistemically different statements — a
hostname is a stable fact, a use case is an interpretation that depends
on an expected policy not yet present at this stage of the project (it
lives in the UseCase/Policy component of the ontology, deliberately
decoupled for now — see the earlier discussion).

The inventory is an EXTERNAL configuration file, maintained by hand,
never derived from observed traffic. If the file is missing, the
pipeline still works, simply without the enrichment — it is never a
requirement.

Every annotation explicitly carries "_source": "external_static_
inventory", so as to leave no ambiguity about what was observed on the
wire and what was declared separately.
"""
from __future__ import annotations
import json
from pathlib import Path

SOURCE_LABEL = "external_static_inventory"


def load(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def _hint_for(ip: str | None, inventory: dict[str, str]) -> str | None:
    if not ip:
        return None
    return inventory.get(ip)


def annotate(records: list[dict], inventory: dict[str, str]) -> int:
    """Adds, where possible, an 'asset_hint' field — it never overwrites
    observed fields, it only adds a label explicitly marked as coming
    from external configuration.
    Returns the number of annotated records."""
    if not inventory:
        return 0

    annotated = 0
    for rec in records:
        hint: dict[str, str] = {}

        # TLS / SSH: src_ip, dst_ip
        src = _hint_for(rec.get("src_ip"), inventory)
        dst = _hint_for(rec.get("dst_ip"), inventory)
        # IPsec IKE: local_addr, remote_addr
        local = _hint_for(rec.get("local_addr"), inventory)
        remote = _hint_for(rec.get("remote_addr"), inventory)

        if src:
            hint["src_hostname"] = src
        if dst:
            hint["dst_hostname"] = dst
        if local:
            hint["local_hostname"] = local
        if remote:
            hint["remote_hostname"] = remote

        if hint:
            hint["_source"] = SOURCE_LABEL
            rec["asset_hint"] = hint
            annotated += 1

    return annotated
