# -*- coding: utf-8 -*-
"""
scanner.py — recursive discovery of the raw data sources under shared/.

It does not assume a fixed list of sensors: it scans shared/ and
classifies what it finds based on the real structure (zeeklogs/*.log,
ipsec_status.txt), not on the host name. This means adding a sensor (as
happened with svca) requires no change here.

Naming convention: the folder under shared/ is the sensor's identity
("mainfw-eth0", "bastion-eth0", "dmzgw", "svca", ...) — for hosts with
several monitored interfaces, the folder name includes the interface;
for the others, it matches the hostname.
"""
from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass, field

ZEEK_LOG_KINDS = ("ssl", "ssh", "x509", "smtp", "conn")


@dataclass
class SensorSource:
    sensor_id: str          # name of the folder under shared/ (= the sensor's identity)
    zeek_logs: dict = field(default_factory=dict)   # {"ssl": Path, "ssh": Path, ...}
    ipsec_status: Path | None = None
    ipsec_conns: Path | None = None
    ipsec_static_config: Path | None = None


def discover_sources(shared_root: Path) -> list[SensorSource]:
    """Scans shared_root and returns a SensorSource for every subfolder
    containing at least one recognized source. Empty or irrelevant
    subfolders are silently ignored."""
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

        ipsec_conns_file = entry / "ipsec_conns.txt"
        if ipsec_conns_file.is_file() and ipsec_conns_file.stat().st_size > 0:
            src.ipsec_conns = ipsec_conns_file

        ipsec_config_file = entry / "swanctl_config.txt"
        if ipsec_config_file.is_file() and ipsec_config_file.stat().st_size > 0:
            src.ipsec_static_config = ipsec_config_file

        if src.zeek_logs or src.ipsec_status or src.ipsec_conns or src.ipsec_static_config:
            sources.append(src)

    return sources
