# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# crypto_levels.py — multi-dimensional cryptographic classification
#
# Same logic as pipeline_cbom/normalizer.py (KEX/CIPHER/MAC/HOSTKEY/
# HASH, SAFE/MARGINAL/VULNERABLE/BROKEN scale), duplicated here — not
# imported — because cbom_backend and pipeline_cbom are two packages
# distributed separately, each with its own dependencies (this service
# does not and must not depend on pipeline_cbom).
#
# The duplication is declared explicitly, not hidden: if the tables in
# pipeline_cbom/normalizer.py change, this file must be updated by hand
# accordingly. It is the same principle of "data declared externally,
# never silent" applied here to the dependency between the two modules
# instead of to a domain datum.
#
# Why compare LEVELS and not exact strings: the Expected profile (filled
# in by the operator in the GUI, with entries such as "ECP384 (gr20)" or
# "AES-256-GCM") and the Observed profile (produced by pipeline_cbom on
# real traffic, with entries such as "ECP_384" or
# "TLS_AES_256_GCM_SHA384") use different syntaxes for the same concepts.
# Building a string-by-string correspondence table between the two
# syntaxes would be a third place where the two sources could silently
# drift apart. Classifying both on the same 4-level scale, with the same
# reference tables, and comparing only the resulting level avoids the
# problem at its root.
# =====================================================================
from __future__ import annotations
import re

SAFE, MARGINAL, VULNERABLE, BROKEN, UNKNOWN, NA = (
    "SAFE", "MARGINAL", "VULNERABLE", "BROKEN", "UNKNOWN", "NOT_APPLICABLE"
)
# Fifth level, KEX only: a classical+PQ hybrid (e.g.
# sntrup761x25519-sha512, X25519MLKEM768) is not "just as secure" as a
# SAFE classical KEX such as x25519 — it is structurally better prepared,
# because it stays secure even if the classical component is broken by a
# future quantum computer. Treating them as equivalent (as the previous
# version of this module did, both SAFE(1.00)) was a conceptual error,
# not just a calibration one: it hid the whole crypto-agility advantage
# behind a common ceiling. SAFE_PQ is not a FURTHER tier beyond SAFE — it
# is the SAME classical robustness tier, plus the property of also
# resisting a quantum adversary: the severity of a missing SAFE_PQ when
# required therefore reflects a real risk (future exposure), not a harsher
# judgment on present-day security.
SAFE_PQ = "SAFE_PQ"

# Increasing order of robustness — used for the Expected/Observed comparison.
LEVEL_SCORE = {BROKEN: 0.0, VULNERABLE: 0.34, MARGINAL: 0.67, SAFE: 1.0, SAFE_PQ: 1.33}

# Recognized tokens of classical+PQ hybrid or native PQ algorithms, for
# the KEX dimension only — verified against real sources (OpenSSH
# 9.0+/9.9+, IETF draft-ietf-tls-ecdhe-mlkem), not assumed. They drive the
# SAFE_PQ robustness tier of the KEX dimension; the categorical PQC posture
# (pq_readiness) is derived separately by kex_pq_posture() below, from the
# same field (kex) and with its own token lists — the tier answers "how
# strong is this KEX", the posture answers "classical / hybrid / native".
_PQ_HYBRID_TOKENS = (
    "kyber", "mlkem", "ml-kem", "frodokem", "ntru", "saber", "sikeobsolete",
)


# ── KEX / DH groups / curves — threatened by Shor, not by Grover ─────────
# Three different real vocabularies for the same concepts, verified
# against the actual output of the tools (not assumed):
#   - Zeek ssl.log (curve):          "x25519", "secp256r1", "secp384r1"
#   - swanctl --list-sas (runtime):  "ECP_384", "MODP_2048" (uppercase, underscore)
#   - swanctl.conf (declared):       "ecp384", "modp2048" (lowercase, no underscore)
# All three must classify correctly, or the Observed comparison silently
# fails on an entire protocol (IPsec, precisely the case where it was
# found: "ECP_384" was not recognized).
#
# Keys already stripped of dashes/underscores: kex_level normalizes the
# input the same way before looking it up, so a single entry covers
# "ECP_384", "ecp384", "ECP-384" — three different real vocabularies for
# the same concept (swanctl runtime, swanctl.conf, hypothetical dashed
# variants), verified against the actual output of the tools.
_KEX_TABLE = {
    "x25519": SAFE, "curve25519": SAFE,
    "ecp384": MARGINAL, "nistp384": MARGINAL, "secp384r1": MARGINAL, "p384": MARGINAL,
    "ecp256": MARGINAL, "nistp256": MARGINAL, "secp256r1": MARGINAL, "p256": MARGINAL,
    "ecp521": MARGINAL, "p521": MARGINAL,
    "modp4096": VULNERABLE, "group16": VULNERABLE,
    "modp2048": VULNERABLE, "group14": VULNERABLE,
    "modp1024": BROKEN, "group1": BROKEN,
    "p224": BROKEN,
}


def kex_level(text: str | None) -> str:
    if not text:
        return UNKNOWN
    norm = text.lower().replace("-", "").replace("_", "")
    # Checked BEFORE the classical table: "sntrup761x25519sha512" contains
    # "x25519" (a SAFE classical token) — without this early check, the
    # hybrid would fall on the x25519 entry of the table below and lose
    # its higher classification.
    if any(tok.replace("-", "") in norm for tok in _PQ_HYBRID_TOKENS):
        return SAFE_PQ
    for token, level in _KEX_TABLE.items():
        if token in norm:
            return level
    return UNKNOWN


# ── CIPHER: symmetric algorithm + length — threatened by Grover ──────────
def cipher_level(text: str | None) -> str:
    if not text:
        return UNKNOWN
    t = text.lower()
    if "3des" in t or t.strip() == "des":
        return BROKEN
    if "rc4" in t:
        return BROKEN
    if "aes" in t or "chacha20" in t.replace("-", "").replace("_", ""):
        m = re.search(r"(128|192|256)", t)
        bits = int(m.group(1)) if m else None
        is_cbc = "cbc" in t  # non-AEAD: no built-in authentication,
                              # well-known history of padding-oracle
                              # vulnerabilities (BEAST, Lucky13) — see also
                              # why TLS 1.3 removes every CBC construction.
        if bits is None:
            if "chacha20" in t.replace("-", "").replace("_", ""):
                return SAFE
            return UNKNOWN
        if is_cbc:
            return MARGINAL if bits >= 256 else VULNERABLE
        if bits >= 256:
            return SAFE
        if bits >= 128:
            return MARGINAL
        return VULNERABLE
    return UNKNOWN


# ── HASH / PRF / signature — threatened by Grover ────────────────────────
_HASH_TABLE = {
    "sha384": SAFE, "sha512": SAFE,
    "sha256": MARGINAL,
    "sha1": BROKEN,
    "md5": BROKEN,
}


def hash_level(text: str | None) -> str:
    if not text:
        return UNKNOWN
    norm = text.lower().replace("-", "").replace("_", "").replace("sha2", "sha")
    for token, level in _HASH_TABLE.items():
        if token in norm:
            return level
    return UNKNOWN


# ── MAC: if AEAD (GCM/Poly1305) integrity is intrinsic; otherwise the
# robustness follows that of the underlying hash function (HMAC-SHA2-384
# as IPsec PRF, hmac-sha2-256-etm as SSH, etc.) ─────────────────────────────
def mac_level(cipher_text: str | None, mac_text: str | None) -> str:
    combined = f"{cipher_text or ''} {mac_text or ''}".lower()
    if not combined.strip():
        return UNKNOWN
    if "gcm" in combined or "poly1305" in combined:
        return SAFE

    # Normalizes separators AND the "SHA2" acronym (the SHA-2 family, not a
    # separator) before looking for the strength of the underlying hash:
    # "sha2-384", "SHA2_384", "sha-384" all become "sha384" — avoids listing
    # by hand every combination used by the different sources
    # (swanctl: "HMAC_SHA2_384"; SSH: "hmac-sha2-256-etm"; TLS: "SHA384").
    norm = combined.replace("-", "").replace("_", "").replace("sha2", "sha")
    is_etm = "etm" in norm

    if "sha384" in norm or "sha512" in norm:
        return SAFE
    if "sha256" in norm:
        return SAFE if is_etm else MARGINAL
    if "sha1" in norm:
        return VULNERABLE if is_etm else BROKEN
    if "md5" in norm:
        return BROKEN
    return UNKNOWN


# ── HOSTKEY: type and size of the identity key ───────────────────────────
def hostkey_level(text: str | None) -> str:
    if not text:
        return UNKNOWN
    t = text.lower()
    if "ed25519" in t:
        return SAFE
    if "ecdsa" in t or (("p-" in t or re.search(r"\bp\d{3}\b", t)) and "rsa" not in t):
        m = re.search(r"(256|384|521)", t)
        bits = int(m.group(1)) if m else None
        if bits is None:
            return UNKNOWN
        return SAFE if bits >= 384 else MARGINAL
    if "rsa" in t:
        m = re.search(r"(2048|3072|4096)", t)
        bits = int(m.group(1)) if m else None
        if bits is None:
            return UNKNOWN
        if bits >= 3072:
            return SAFE
        if bits >= 2048:
            return MARGINAL
        return VULNERABLE
    if "dsa" in t:
        return BROKEN
    return UNKNOWN


# ── POST-QUANTUM POSTURE: a property of the KEY EXCHANGE only ─────────────
# The single definition of pq_readiness in the whole backend, applied with
# the SAME function to the SAME field on both sides of the comparison:
#   - Expected: graph_writer._derive_expected_pq_postures() → expected.kex
#     (TLS curve / SSH KEX, from the GUI) or ike_sa.kex (IPsec)
#   - Observed: cbom_loader → observed kex (Zeek curve / kex_alg, swanctl
#     IKE group plus any additional key exchanges)
# Mirrored 1:1 for the GUI preview by kexPQPosture() in app.js (same token
# lists, same rules): if you change one, change the other.
#
# Why the key exchange ONLY, and not signatures/ciphers/MACs: the threat the
# posture feeds (harvest-now, decrypt-later, see graph_writer
# ._compute_quantum_risk) is a passive adversary recording traffic today and
# recovering the session keys later with a quantum computer. What protects
# recorded traffic is exclusively how the session keys were established. A
# post-quantum signature (FALCON, ML-DSA, XMSS...) protects authentication
# at connection time — it cannot be forged retroactively — but does nothing
# for confidentiality of traffic already captured; symmetric ciphers and
# MACs are affected only by Grover and are assessed by their own dimensions.
# An earlier version derived the posture from every selected primitive, so a
# PQ signature on top of a classical KEX turned the posture "hybrid" and
# silenced the HNDL flag: a false negative, now removed by construction.
#
# Rules, on the bare algorithm name (any GUI annotation in parentheses, such
# as "(hybrid PQ)", is stripped first so that both sides classify the same
# vocabulary — the posture is never read from a label):
#   PQ KEM token + classical token → "hybrid (classical+PQ)"
#   PQ KEM token only              → "native PQ"
#   no PQ KEM token (or no KEX)    → "classical"
POSTURE_CLASSICAL = "classical"
POSTURE_HYBRID = "hybrid (classical+PQ)"
POSTURE_NATIVE = "native PQ"

_PQ_KEM_TOKENS = (
    "mlkem", "kyber", "sntrup", "ntruprime", "frodokem", "bike", "hqc", "mceliece",
)
_CLASSICAL_KEX_TOKENS = (
    "x25519", "x448", "curve25519", "curve448", "secp", "prime256", "brainpool",
    "p256", "p384", "p521", "nistp", "ecp", "ecdh", "modp", "ffdhe",
)


def kex_pq_posture(kex: str | None) -> str:
    if not kex:
        return POSTURE_CLASSICAL
    name = kex.split(" (")[0]
    norm = name.lower().replace("-", "").replace("_", "").replace(".", "").replace(" ", "")
    if not any(tok in norm for tok in _PQ_KEM_TOKENS):
        return POSTURE_CLASSICAL
    if any(tok in norm for tok in _CLASSICAL_KEX_TOKENS):
        return POSTURE_HYBRID
    return POSTURE_NATIVE


DIMENSION_CLASSIFIERS = {
    "kex": kex_level,
    "hash": hash_level,
    "host_key": hostkey_level,
}
