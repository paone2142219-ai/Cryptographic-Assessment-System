# -*- coding: utf-8 -*-
"""
correlate.py — fusione di fonti ETEROGENEE che descrivono lo stesso
evento da angolazioni diverse. Non è deduplicazione: qui i record di
partenza non sono ridondanti, sono complementari, e la fusione arricchisce
un record invece di scartarne uno.

Correlazione implementata: TLS <-> x509, via cert_chain_fps. Un record
TLS con cert_chain_fps popolato (quindi non TLS 1.3, o TLS 1.3 con
osservazione riuscita per altra via) viene arricchito con il dettaglio
completo del certificato, incluso il proprio pqc_assessment sulla
dimensione HOSTKEY — dimensione che il solo record TLS non può valutare
da sé (vedi normalizer.normalize_tls, HOSTKEY resta UNKNOWN finché non
correlato qui).
"""
from __future__ import annotations


def correlate_tls_with_certs(tls_records: list[dict], cert_index: dict[str, dict]) -> int:
    """Arricchisce in-place i record TLS con il certificato corrispondente.
    Restituisce il numero di correlazioni riuscite."""
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
        # La dimensione HOSTKEY del record TLS era UNKNOWN perché il solo
        # ssl.log non porta il dettaglio della chiave — ora che il
        # certificato è correlato, si eredita la sua valutazione.
        if "pqc_assessment" in rec and "pqc_assessment" in cert:
            rec["pqc_assessment"]["HOSTKEY"] = cert["pqc_assessment"]["HOSTKEY"]
        correlated += 1
    return correlated
