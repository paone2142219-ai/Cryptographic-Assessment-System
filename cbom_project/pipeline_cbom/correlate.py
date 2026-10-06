# -*- coding: utf-8 -*-
"""
correlate.py — merging of HETEROGENEOUS sources describing the same
event from different angles. It is not deduplication: here the starting
records are not redundant, they are complementary, and the merge
enriches a record instead of discarding one.

Two correlations implemented:
  1. TLS <-> x509, via cert_chain_fps.
  2. TLS <-> SMTP, via uid (same connection, two different Zeek analyzers
     on the same traffic).
"""
from __future__ import annotations


def correlate_tls_with_certs(tls_records: list[dict], cert_index: dict[str, dict]) -> int:
    """Enriches the TLS records in place with the matching certificate.
    Returns the number of successful correlations."""
    correlated = 0
    for rec in tls_records:
        fps = rec.get("cert_chain_fps") or []
        if not fps:
            continue
        leaf_fp = fps[0]
        cert = cert_index.get(leaf_fp)
        if cert is None:
            continue

        rec["certificate"] = {
            "fingerprint": cert["fingerprint"],
            "subject": cert["subject"],
            "issuer": cert["issuer"],
            "key_type": cert["key_type"],
            "key_length": cert["key_length"],
            "curve": cert.get("curve"),
            "sig_alg": cert["sig_alg"],
            "not_valid_after": cert["not_valid_after"],
            "observed_by": cert["observed_by"],
        }
        # The HOSTKEY dimension of the TLS record was UNKNOWN because
        # ssl.log alone does not carry the key details — now that the
        # certificate is correlated, its assessment is inherited.
        if "pqc_assessment" in rec and "pqc_assessment" in cert:
            rec["pqc_assessment"]["HOSTKEY"] = cert["pqc_assessment"]["HOSTKEY"]
        correlated += 1
    return correlated


def correlate_smtp_with_tls(smtp_records: list[dict], tls_records: list[dict]) -> int:
    """Enriches the TLS records in place with the SMTP context of the same
    Zeek UID (same connection, two different analyzers on the same
    traffic). Explicitly flags when the two sources disagree instead of
    silently letting one of them win.

    Returns the number of successful correlations."""
    smtp_by_uid = {r["uid"]: r for r in smtp_records if r.get("uid")}
    correlated = 0

    for rec in tls_records:
        uid = rec.get("uid")
        if not uid or uid not in smtp_by_uid:
            continue
        smtp = smtp_by_uid[uid]

        rec["application_protocol"] = "SMTP"
        rec["smtp_context"] = {
            "helo": smtp.get("helo"),
            "last_reply": smtp.get("last_reply"),
            "starttls_confirmed_by_smtp_log": smtp.get("starttls_confirmed"),
        }
        # Two independent sources (Zeek's SMTP analyzer and TLS analyzer)
        # should agree that the session switched to TLS. If they do not
        # agree, it is an anomaly to flag, not to flatten by choosing
        # which source to believe.
        rec["smtp_tls_consistency"] = (
            "consistent" if smtp.get("starttls_confirmed") and rec.get("established")
            else "MISMATCH_investigate"
        )
        correlated += 1

    return correlated
