#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py — pipeline_cbom, esecuzione manuale/a comando (mai automatica).

Uso:
    python3 main.py --shared /percorso/a/shared --output cbom.json

Rilettura completa di shared/ a ogni esecuzione (nessuno stato tra un
run e l'altro): a questa scala, più semplice e più robusto di un
tracciamento incrementale — vedi discussione di design.

Fasi, in ordine:
  1. scanner.discover_sources    — trova le fonti grezze
  2. parsers/*                    — estrae record intermedi per protocollo
  3. normalizer.normalize_*       — assegna la valutazione PQC multi-dimensionale
  4. dedup.deduplicate            — rimuove doppioni stretti (stesso sensore, stessa sessione)
  5. correlate.correlate_*        — fonde fonti eterogenee complementari
  6. scrittura della CBOM finale (JSON unico)
"""
from __future__ import annotations
import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline_cbom import scanner, dedup, correlate, normalizer
from pipeline_cbom.parsers import tls_parser, ssh_parser, x509_parser, ipsec_parser

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("pipeline_cbom")


def extract(shared_root: Path) -> dict:
    sources = scanner.discover_sources(shared_root)
    log.info(f"Fonti scoperte: {len(sources)} sensori — {[s.sensor_id for s in sources]}")

    tls_records: list[dict] = []
    ssh_records: list[dict] = []
    ike_records: list[dict] = []
    cert_indexes: list[dict[str, dict]] = []

    for src in sources:
        if "ssl" in src.zeek_logs:
            recs = tls_parser.parse(src.zeek_logs["ssl"], src.sensor_id)
            tls_records.extend(recs)
            log.info(f"  {src.sensor_id}: {len(recs)} record TLS")
        if "ssh" in src.zeek_logs:
            recs = ssh_parser.parse(src.zeek_logs["ssh"], src.sensor_id)
            ssh_records.extend(recs)
            log.info(f"  {src.sensor_id}: {len(recs)} record SSH")
        if "x509" in src.zeek_logs:
            idx = x509_parser.parse(src.zeek_logs["x509"], src.sensor_id)
            cert_indexes.append(idx)
            log.info(f"  {src.sensor_id}: {len(idx)} certificati")
        if src.ipsec_status:
            recs = ipsec_parser.parse(src.ipsec_status, src.sensor_id)
            ike_records.extend(recs)
            log.info(f"  {src.sensor_id}: {len(recs)} IKE SA")

    return {
        "tls": tls_records,
        "ssh": ssh_records,
        "ike": ike_records,
        "cert_index": x509_parser.merge_cert_indexes(cert_indexes),
    }


def transform(extracted: dict) -> dict:
    tls_records = [normalizer.normalize_tls(r) for r in extracted["tls"]]
    ssh_records = [normalizer.normalize_ssh(r) for r in extracted["ssh"]]

    ike_records = []
    for ike in extracted["ike"]:
        ike = normalizer.normalize_ipsec_ike(ike)
        ike["child_sas"] = [normalizer.normalize_ipsec_esp(c) for c in ike["child_sas"]]
        ike_records.append(ike)

    cert_index = {fp: normalizer.normalize_certificate(c)
                  for fp, c in extracted["cert_index"].items()}

    dedup_input = tls_records + ssh_records
    deduped, n_removed = dedup.deduplicate(dedup_input)
    log.info(f"Deduplicazione: {n_removed} doppioni stretti rimossi")

    deduped_tls = [r for r in deduped if r["protocol"] == "TLS"]
    deduped_ssh = [r for r in deduped if r["protocol"] == "SSH"]

    n_correlated = correlate.correlate_tls_with_certs(deduped_tls, cert_index)
    log.info(f"Correlazione TLS<->certificato: {n_correlated} record arricchiti")

    return {
        "tls": deduped_tls,
        "ssh": deduped_ssh,
        "ike": ike_records,
        "certificates": list(cert_index.values()),
        "duplicates_removed": n_removed,
        "certificates_correlated": n_correlated,
    }


def load(transformed: dict, shared_root: Path) -> dict:
    connections = transformed["tls"] + transformed["ssh"] + transformed["ike"]
    sensor_ids = sorted({
        sid for rec in connections
        for sid in (rec.get("seen_by") or [rec.get("sensor_id")])
        if sid
    })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(shared_root),
        "summary": {
            "sensor_ids": sensor_ids,
            "connection_count": len(connections),
            "certificate_count": len(transformed["certificates"]),
            "duplicates_removed": transformed["duplicates_removed"],
            "certificates_correlated": transformed["certificates_correlated"],
        },
        "connections": connections,
        "certificates": transformed["certificates"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="pipeline_cbom — consolidamento manuale/a comando")
    parser.add_argument("--shared", required=True, help="percorso della cartella shared/")
    parser.add_argument("--output", required=True, help="percorso del file CBOM JSON di output")
    args = parser.parse_args()

    shared_root = Path(args.shared)
    if not shared_root.is_dir():
        log.error(f"Cartella non trovata: {shared_root}")
        return 1

    extracted = extract(shared_root)
    transformed = transform(extracted)
    cbom = load(transformed, shared_root)

    out_path = Path(args.output)
    out_path.write_text(json.dumps(cbom, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info(f"CBOM scritta in {out_path} — {cbom['summary']['connection_count']} connessioni, "
             f"{cbom['summary']['certificate_count']} certificati")
    return 0


if __name__ == "__main__":
    sys.exit(main())
