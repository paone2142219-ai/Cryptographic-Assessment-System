# -*- coding: utf-8 -*-
"""
dedup.py — removal of STRICT duplicates: the same session, the same
observed protocol type, seen by more than one sensor purely because of
network topology (e.g. mainfw-eth1 and dmzgw before the BPF filter
applied on bastion).

It deliberately does NOT try to correlate heterogeneous sources (Zeek +
VICI, TLS + x509): that is the job of correlate.py, with a different
semantics (merging complementary partial views, not discarding a
duplicate).

Match key: same 5-tuple (protocol, src_ip, src_port, dst_ip, dst_port)
within a narrow time window (default 2 seconds — in observed practice
real duplicates differ by 100-300 microseconds, the propagation time
between two capture points; 2 seconds leaves a wide margin without
risking merging short, close together but genuinely distinct sessions
between the same pair of hosts).
"""
from __future__ import annotations

DEFAULT_TOLERANCE_SECONDS = 2.0


def _key(rec: dict) -> tuple:
    return (rec.get("protocol"), rec.get("src_ip"), rec.get("src_port"),
            rec.get("dst_ip"), rec.get("dst_port"))


def _completeness(rec: dict) -> int:
    """Number of fields with an informative value — used to establish
    which record of the cluster is the most complete view of the session."""
    return sum(1 for v in rec.values() if v not in (None, [], {}, "", 0))


def _merge_cluster(cluster: list[dict]) -> dict:
    """Merges the duplicate records into a single one. It does not pick
    'the first by timestamp' — it picks the most complete one as the base,
    then fills any still-empty fields with what is found in the others. A
    sensor that saw only the start of a session (e.g. mainfw-eth0, before
    the handshake completed) must never cause the loss of the detail
    captured by a sensor that saw the whole session."""
    ordered = sorted(cluster, key=_completeness, reverse=True)
    merged = dict(ordered[0])
    for rec in ordered[1:]:
        for k, v in rec.items():
            if merged.get(k) in (None, [], {}, "", 0) and v not in (None, [], {}, "", 0):
                merged[k] = v
    return merged


def deduplicate(records: list[dict], tolerance: float = DEFAULT_TOLERANCE_SECONDS) -> tuple[list[dict], int]:
    """Returns (deduplicated_records, number_of_duplicates_removed).

    Every surviving record gains a 'seen_by' field, the list of sensors
    that observed that same session — provenance information must not be
    lost even when the record itself is discarded as a duplicate."""
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
            merged = _merge_cluster(cluster)
            merged["seen_by"] = sorted({r["sensor_id"] for r in cluster})
            kept.append(merged)
            removed += len(cluster) - 1

    return kept, removed
