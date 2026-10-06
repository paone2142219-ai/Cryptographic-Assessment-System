# -*- coding: utf-8 -*-
"""
scanner.py — scoperta ricorsiva delle fonti dati grezze sotto shared/.

Non assume una lista fissa di sensori: scandisce shared/ e classifica ciò
che trova in base alla struttura reale (zeeklogs/*.log, ipsec_status.txt),
non al nome dell'host. Questo significa che aggiungere un sensore (come è
successo con svca) non richiede alcuna modifica qui.

Convenzione di naming: la cartella sotto shared/ è l'identità del sensore
("mainfw-eth0", "bastion-eth0", "dmzgw", "svca", ...) — per gli host con
più interfacce monitorate, il nome della cartella include l'interfaccia;
per gli altri, coincide con l'hostname.
"""
from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass, field

ZEEK_LOG_KINDS = ("ssl", "ssh", "x509", "smtp", "conn")


@dataclass
class SensorSource:
    sensor_id: str          # nome della cartella sotto shared/ (= identità del sensore)
    zeek_logs: dict = field(default_factory=dict)   # {"ssl": Path, "ssh": Path, ...}
    ipsec_status: Path | None = None


def discover_sources(shared_root: Path) -> list[SensorSource]:
    """Scandisce shared_root e restituisce una SensorSource per ogni
    sottocartella che contiene almeno un log Zeek riconosciuto o un
    ipsec_status.txt. Sottocartelle vuote o irrilevanti vengono ignorate
    silenziosamente."""
    sources: list[SensorSource] = []
    if not shared_root.is_dir():
        return sources

    for entry in sorted(shared_root.iterdir()):
        if not entry.is_dir():
            continue
        src = SensorSource(sensor_id=entry.name)

        zeeklogs_dir = entry / "zeeklogs"
        if zeeklogs_dir.is_dir():
            for kind in ZEEK_LOG_KINDS:
                candidate = zeeklogs_dir / f"{kind}.log"
                if candidate.is_file() and candidate.stat().st_size > 0:
                    src.zeek_logs[kind] = candidate

        ipsec_file = entry / "ipsec_status.txt"
        if ipsec_file.is_file() and ipsec_file.stat().st_size > 0:
            src.ipsec_status = ipsec_file

        if src.zeek_logs or src.ipsec_status:
            sources.append(src)

    return sources
