# -*- coding: utf-8 -*-
"""
normalizer.py — assigns each record a PQC assessment across five
independent dimensions (KEX, CIPHER, MAC, HOSTKEY, HASH), each on a
four-level scale (SAFE/MARGINAL/VULNERABLE/BROKEN), mapped to three
quantum threat paradigms (HNDL, SHOR, GROVER).

The tables are deliberately non-exhaustive: they cover the algorithms
observed in the lab plus the most common variants, not the whole IANA
space — they must be extended when an unmapped algorithm appears (never
inferred: an algorithm missing from the table gets UNKNOWN, never an
optimistic default).
"""
from __future__ import annotations

SAFE, MARGINAL, VULNERABLE, BROKEN, UNKNOWN, NA = (
    "SAFE", "MARGINAL", "VULNERABLE", "BROKEN", "UNKNOWN", "NOT_APPLICABLE"
)

# ── KEX: DH/ECDH groups/curves — threatened by Shor, not by Grover ──────────
_KEX_TABLE = {
    "x25519": SAFE, "X25519": SAFE, "curve25519-sha256": SAFE,
    "secp256r1": MARGINAL, "prime256v1": MARGINAL, "ECP_256": MARGINAL,
    "secp384r1": MARGINAL, "ECP_384": MARGINAL,
    "secp521r1": MARGINAL, "ECP_521": MARGINAL,
    "MODP_2048": VULNERABLE, "MODP_1536": BROKEN, "MODP_1024": BROKEN,
}

# ── CIPHER: symmetric algorithm + key length — threatened by Grover, not by Shor ──
def _cipher_level(enc: str | None, bits: int | None) -> str:
    if enc is None:
        return UNKNOWN
    enc_u = enc.upper()
    if "AES" in enc_u or "CHACHA20" in enc_u.replace("-", "").replace("_", ""):
        if bits is None:
            return UNKNOWN
        if bits >= 256:
            return SAFE
        if bits >= 128:
            return MARGINAL
        return VULNERABLE
    if "3DES" in enc_u or "DES" in enc_u:
        return BROKEN
    if "RC4" in enc_u:
        return BROKEN
    return UNKNOWN


# ── HASH: hash/PRF/signature functions — threatened by Grover (collisions: Shor does not apply) ──
_HASH_TABLE = {
    "SHA384": SAFE, "SHA2_384": SAFE, "SHA512": SAFE, "SHA2_512": SAFE,
    "SHA256": MARGINAL, "SHA2_256": MARGINAL,
    "SHA1": BROKEN, "SHA-1": BROKEN,
    "MD5": BROKEN,
}

# ── HOSTKEY: type and size of the identity key (SSH host key, certificates) ──
def _hostkey_level(key_type: str | None, bits: int | None) -> str:
    if key_type is None:
        return UNKNOWN
    kt = key_type.lower()
    if "ed25519" in kt:
        return SAFE
    if "ecdsa" in kt or "ec" in kt:
        if bits is None:
            return UNKNOWN
        return SAFE if bits >= 256 else MARGINAL
    if "rsa" in kt:
        if bits is None:
            return UNKNOWN
        if bits >= 3072:
            return SAFE
        if bits >= 2048:
            return MARGINAL
        return VULNERABLE
    if "dsa" in kt:
        return BROKEN
    return UNKNOWN


def _dim(level: str, paradigm: str) -> dict:
    return {"level": level, "quantum_paradigm": paradigm}


def _extract_hash_token(*names: str | None) -> str | None:
    for name in names:
        if not name:
            continue
        up = name.upper()
        for token in ("SHA384", "SHA2_384", "SHA512", "SHA2_512",
                      "SHA256", "SHA2_256", "SHA1", "SHA-1", "MD5"):
            if token.replace("-", "") in up.replace("-", ""):
                return token
    return None


def normalize_tls(rec: dict) -> dict:
    cipher = rec.get("cipher") or ""
    enc_bits = 256 if "256" in cipher else (128 if "128" in cipher else None)
    hash_token = _extract_hash_token(cipher)

    kex_level = UNKNOWN
    curve = rec.get("curve")
    if curve:
        kex_level = _KEX_TABLE.get(curve, UNKNOWN)
    elif rec.get("tls_version") == "TLSv13" and rec.get("resumed"):
        kex_level = NA  # PSK-only resumption: no KEX in this handshake

    assessment = {
        "KEX": _dim(kex_level, "HNDL/SHOR"),
        "CIPHER": _dim(_cipher_level(cipher, enc_bits), "GROVER"),
        "MAC": _dim(SAFE if "GCM" in cipher or "POLY1305" in cipher else UNKNOWN, "GROVER"),
        "HOSTKEY": _dim(UNKNOWN, "HNDL/SHOR"),  # requires the correlated certificate — see correlate.py
        "HASH": _dim(_HASH_TABLE.get(hash_token, UNKNOWN) if hash_token else UNKNOWN, "GROVER"),
    }
    rec["pqc_assessment"] = assessment
    return rec


def normalize_ssh(rec: dict) -> dict:
    kex = rec.get("kex_alg") or ""
    kex_level = UNKNOWN
    for token, level in _KEX_TABLE.items():
        if token.lower() in kex.lower():
            kex_level = level
            break

    cipher = rec.get("cipher_alg") or ""
    enc_bits = 256 if "256" in cipher else (128 if "128" in cipher else None)

    mac = rec.get("mac_alg") or ""
    mac_level = SAFE if ("etm" in mac.lower() or "poly1305" in cipher.lower()
                          or "gcm" in cipher.lower()) else (
        UNKNOWN if not mac else MARGINAL
    )

    assessment = {
        "KEX": _dim(kex_level, "HNDL/SHOR"),
        "CIPHER": _dim(_cipher_level(cipher, enc_bits), "GROVER"),
        "MAC": _dim(mac_level, "GROVER"),
        "HOSTKEY": _dim(_hostkey_level(rec.get("host_key_alg"), None), "HNDL/SHOR"),
        "HASH": _dim(UNKNOWN, "GROVER"),
    }
    rec["pqc_assessment"] = assessment
    return rec


def normalize_ipsec_ike(rec: dict) -> dict:
    kex_level = _KEX_TABLE.get(rec.get("ike_group"), UNKNOWN)
    hash_token = _extract_hash_token(rec.get("ike_prf"))
    assessment = {
        "KEX": _dim(kex_level, "HNDL/SHOR"),
        "CIPHER": _dim(_cipher_level(rec.get("ike_enc"), rec.get("ike_enc_bits")), "GROVER"),
        "MAC": _dim(SAFE if rec.get("ike_enc", "").upper().find("GCM") >= 0 else UNKNOWN, "GROVER"),
        "HOSTKEY": _dim(NA, "N/A"),  # IKE authentication assessed separately (PSK or certificate)
        "HASH": _dim(_HASH_TABLE.get(hash_token, UNKNOWN) if hash_token else UNKNOWN, "GROVER"),
    }
    rec["pqc_assessment"] = assessment
    return rec


def normalize_ipsec_esp(rec: dict) -> dict:
    if not rec.get("has_pfs"):
        kex_level = NA
    else:
        kex_level = _KEX_TABLE.get(rec.get("esp_group"), UNKNOWN)
    assessment = {
        "KEX": _dim(kex_level, "HNDL/SHOR"),
        "CIPHER": _dim(_cipher_level(rec.get("esp_enc"), rec.get("esp_enc_bits")), "GROVER"),
        "MAC": _dim(SAFE if rec.get("esp_enc", "").upper().find("GCM") >= 0 else UNKNOWN, "GROVER"),
        "HOSTKEY": _dim(NA, "N/A"),
        "HASH": _dim(NA, "N/A"),
    }
    rec["pqc_assessment"] = assessment
    return rec


def normalize_certificate(cert: dict) -> dict:
    hash_token = _extract_hash_token(cert.get("sig_alg"))
    assessment = {
        "KEX": _dim(NA, "N/A"),
        "CIPHER": _dim(NA, "N/A"),
        "MAC": _dim(NA, "N/A"),
        "HOSTKEY": _dim(_hostkey_level(cert.get("key_type"), cert.get("key_length")), "HNDL/SHOR"),
        "HASH": _dim(_HASH_TABLE.get(hash_token, UNKNOWN) if hash_token else UNKNOWN, "GROVER"),
    }
    cert["pqc_assessment"] = assessment
    return cert
