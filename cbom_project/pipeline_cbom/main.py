#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py — pipeline_cbom, manual/on-demand execution (never automatic).

Usage:
    python3 main.py --shared /path/to/shared --output cbom.json

Full re-read of shared/ on every run (no state between one run and the
next): at this scale, simpler and more robust than incremental tracking
— see design discussion.

Phases, in order:
  1. scanner.discover_sources    — finds the raw sources
  2. parsers/*                    — extracts intermediate records per protocol
  3. normalizer.normalize_*       — assigns the multi-dimensional PQC assessment
  4. dedup.deduplicate            — removes strict duplicates (same sensor, same session)
  5. correlate.correlate_*        — merges complementary heterogeneous sources
  6. writing of the final CBOM (single JSON)
"""
from __future__ import annotations
import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline_cbom import scanner, dedup, correlate, normalizer, asset_inventory
from pipeline_cbom.parsers import tls_parser, ssh_parser, x509_parser, ipsec_parser, smtp_parser

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("pipeline_cbom")


def extract(shared_root: Path) -> dict:
    sources = scanner.discover_sources(shared_root)
    log.info(f"Sources discovered: {len(sources)} sensors — {[s.sensor_id for s in sources]}")

    tls_records: list[dict] = []
    ssh_records: list[dict] = []
    ike_records: list[dict] = []
    smtp_records: list[dict] = []
    cert_indexes: list[dict[str, dict]] = []
    conn_metadata: dict[str, dict] = {}
    static_config: dict[str, dict] = {}

    for src in sources:
        if "ssl" in src.zeek_logs:
            recs = tls_parser.parse(src.zeek_logs["ssl"], src.sensor_id)
            tls_records.extend(recs)
            log.info(f"  {src.sensor_id}: {len(recs)} TLS records")
        if "ssh" in src.zeek_logs:
            recs = ssh_parser.parse(src.zeek_logs["ssh"], src.sensor_id)
            ssh_records.extend(recs)
            log.info(f"  {src.sensor_id}: {len(recs)} SSH records")
        if "smtp" in src.zeek_logs:
            recs = smtp_parser.parse(src.zeek_logs["smtp"], src.sensor_id)
            smtp_records.extend(recs)
            log.info(f"  {src.sensor_id}: {len(recs)} SMTP records")
        if "x509" in src.zeek_logs:
            idx = x509_parser.parse(src.zeek_logs["x509"], src.sensor_id)
            cert_indexes.append(idx)
            log.info(f"  {src.sensor_id}: {len(idx)} certificates")
        if src.ipsec_status:
            recs = ipsec_parser.parse(src.ipsec_status, src.sensor_id)
            ike_records.extend(recs)
            log.info(f"  {src.sensor_id}: {len(recs)} IKE SAs")
        if src.ipsec_conns:
            meta = ipsec_parser.parse_conns(src.ipsec_conns, src.sensor_id)
            conn_metadata.update(meta)
            log.info(f"  {src.sensor_id}: {len(meta)} configured IPsec connections (auth/rekey)")
        if src.ipsec_static_config:
            conf = ipsec_parser.parse_static_config(src.ipsec_static_config, src.sensor_id)
            static_config.update(conf)
            log.info(f"  {src.sensor_id}: {len(conf)} connections with a declared proposal (static config)")

    return {
        "tls": tls_records,
        "ssh": ssh_records,
        "ike": ike_records,
        "smtp": smtp_records,
        "cert_index": x509_parser.merge_cert_indexes(cert_indexes),
        "conn_metadata": conn_metadata,
        "static_config": static_config,
    }


def transform(extracted: dict) -> dict:
    tls_records = [normalizer.normalize_tls(r) for r in extracted["tls"]]
    ssh_records = [normalizer.normalize_ssh(r) for r in extracted["ssh"]]

    ike_records = []
    for ike in extracted["ike"]:
        ike = normalizer.normalize_ipsec_ike(ike)
        ike["child_sas"] = [normalizer.normalize_ipsec_esp(c) for c in ike["child_sas"]]
        ike_records.append(ike)

    n_conn_meta = ipsec_parser.merge_conn_metadata(ike_records, extracted["conn_metadata"])
    log.info(f"IKE<->configuration metadata correlation (auth/rekey): {n_conn_meta} records enriched")

    n_static = ipsec_parser.merge_static_config(ike_records, extracted["static_config"])
    log.info(f"IKE<->static configuration correlation (declared proposal): {n_static} records enriched")

    cert_index = {fp: normalizer.normalize_certificate(c)
                  for fp, c in extracted["cert_index"].items()}

    dedup_input = tls_records + ssh_records
    deduped, n_removed = dedup.deduplicate(dedup_input)
    log.info(f"Deduplication: {n_removed} strict duplicates removed")

    deduped_tls = [r for r in deduped if r["protocol"] == "TLS"]
    deduped_ssh = [r for r in deduped if r["protocol"] == "SSH"]

    n_correlated = correlate.correlate_tls_with_certs(deduped_tls, cert_index)
    log.info(f"TLS<->certificate correlation: {n_correlated} records enriched")

    n_smtp_correlated = correlate.correlate_smtp_with_tls(extracted["smtp"], deduped_tls)
    log.info(f"SMTP<->TLS correlation: {n_smtp_correlated} records enriched")

    return {
        "tls": deduped_tls,
        "ssh": deduped_ssh,
        "ike": ike_records,
        "certificates": list(cert_index.values()),
        "duplicates_removed": n_removed,
        "certificates_correlated": n_correlated,
        "smtp_correlated": n_smtp_correlated,
        "ipsec_conn_metadata_correlated": n_conn_meta,
        "ipsec_static_config_correlated": n_static,
    }


def load(transformed: dict, shared_root: Path, inventory: dict[str, str]) -> dict:
    connections = transformed["tls"] + transformed["ssh"] + transformed["ike"]
    sensor_ids = sorted({
        sid for rec in connections
        for sid in (rec.get("seen_by") or [rec.get("sensor_id")])
        if sid
    })

    n_asset_annotated = asset_inventory.annotate(connections, inventory)
    if inventory:
        log.info(f"Asset inventory: {n_asset_annotated} records annotated "
                  f"({len(inventory)} known addresses, declared external source)")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(shared_root),
        "summary": {
            "sensor_ids": sensor_ids,
            "connection_count": len(connections),
            "certificate_count": len(transformed["certificates"]),
            "duplicates_removed": transformed["duplicates_removed"],
            "certificates_correlated": transformed["certificates_correlated"],
            "smtp_correlated": transformed.get("smtp_correlated", 0),
            "ipsec_conn_metadata_correlated": transformed.get("ipsec_conn_metadata_correlated", 0),
            "ipsec_static_config_correlated": transformed.get("ipsec_static_config_correlated", 0),
            "asset_hints_applied": n_asset_annotated,
        },
        "connections": connections,
        "certificates": transformed["certificates"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="pipeline_cbom — manual/on-demand consolidation")
    parser.add_argument("--shared", required=True, help="path of the shared/ folder")
    parser.add_argument("--output", required=True, help="path of the output CBOM JSON file")
    parser.add_argument("--assets", required=False, default=None,
                         help="path of an IP->hostname inventory (JSON), optional — "
                              "declared external data, never derived from observed traffic")
    args = parser.parse_args()

    shared_root = Path(args.shared)
    if not shared_root.is_dir():
        log.error(f"Folder not found: {shared_root}")
        return 1

    assets_path = Path(args.assets) if args.assets else (
        Path(__file__).resolve().parent / "asset_inventory.json"
    )
    inventory = asset_inventory.load(assets_path if assets_path.is_file() else None)

    extracted = extract(shared_root)
    transformed = transform(extracted)
    cbom = load(transformed, shared_root, inventory)

    out_path = Path(args.output)
    out_path.write_text(json.dumps(cbom, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info(f"CBOM written to {out_path} — {cbom['summary']['connection_count']} connections, "
             f"{cbom['summary']['certificate_count']} certificates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
