# -*- coding: utf-8 -*-
"""
dedup.py — rimozione di doppioni STRETTI: stessa sessione, stesso tipo di
protocollo osservato, vista da più di un sensore per pura topologia di
rete (es. mainfw-eth1 e dmzgw prima del filtro BPF applicato a bastion).

Deliberatamente NON tenta di correlare fonti eterogenee (Zeek + VICI,
TLS + x509): quello è compito di correlate.py, con una semantica diversa
(fusione di viste parziali complementari, non scarto di un duplicato).

Chiave di match: stessa 5-tupla (protocollo, src_ip, src_port, dst_ip,
dst_port) entro una finestra temporale stretta (default 2 secondi — nella
pratica osservata i doppioni reali differiscono di 100-300 microsecondi,
il tempo di propagazione tra due punti di cattura; 2 secondi lascia un
margine ampio senza rischiare di fondere sessioni brevi e ravvicinate ma
genuinamente distinte tra la stessa coppia di host).
"""
from __future__ import annotations

DEFAULT_TOLERANCE_SECONDS = 2.0


def _key(rec: dict) -> tuple:
    return (rec.get("protocol"), rec.get("src_ip"), rec.get("src_port"),
            rec.get("dst_ip"), rec.get("dst_port"))


def deduplicate(records: list[dict], tolerance: float = DEFAULT_TOLERANCE_SECONDS) -> tuple[list[dict], int]:
    """Restituisce (record_deduplicati, numero_doppioni_rimossi).

    Ogni record superstite guadagna un campo 'seen_by', l'elenco dei
    sensori che hanno osservato quella stessa sessione — l'informazione
    di provenienza non va persa nemmeno quando il record stesso viene
    scartato come doppione."""
    buckets: dict[tuple, list[dict]] = {}
    for rec in records:
        buckets.setdefault(_key(rec), []).append(rec)

    kept: list[dict] = []
    removed = 0

    for key, group in buckets.items():
        group.sort(key=lambda r: r.get("ts") or 0)
        clusters: list[list[dict]] = []
        for rec in group:
            placed = False
            for cluster in clusters:
                if abs((rec.get("ts") or 0) - (cluster[-1].get("ts") or 0)) <= tolerance:
                    cluster.append(rec)
                    placed = True
                    break
            if not placed:
                clusters.append([rec])

        for cluster in clusters:
            primary = cluster[0]
            primary["seen_by"] = sorted({r["sensor_id"] for r in cluster})
            kept.append(primary)
            removed += len(cluster) - 1

    return kept, removed
