# -*- coding: utf-8 -*-
"""
normalizer.py — assegna a ciascun record una valutazione PQC su cinque
dimensioni indipendenti (KEX, CIPHER, MAC, HOSTKEY, HASH), ciascuna su
scala a quattro livelli (SAFE/MARGINAL/VULNERABLE/BROKEN), mappata a tre
paradigmi di minaccia quantistica (HNDL, SHOR, GROVER).

Le tabelle sono deliberatamente non esaustive: coprono gli algoritmi
osservati nel laboratorio più le varianti più comuni, non l'intero
spazio IANA — vanno estese quando compare un algoritmo non mappato
(mai inferito: un algoritmo assente dalla tabella riceve UNKNOWN, mai
un default ottimistico).
"""
from __future__ import annotations

SAFE, MARGINAL, VULNERABLE, BROKEN, UNKNOWN, NA = (
    "SAFE", "MARGINAL", "VULNERABLE", "BROKEN", "UNKNOWN", "NOT_APPLICABLE"
)

# ── KEX: gruppi DH/ECDH/curve — minacciati da Shor, non da Grover ──────────
_KEX_TABLE = {
    # Classici
    "x25519": SAFE, "X25519": SAFE, "curve25519-sha256": SAFE,
    "secp256r1": MARGINAL, "prime256v1": MARGINAL, "ECP_256": MARGINAL,
    "secp384r1": MARGINAL, "ECP_384": MARGINAL,
    "secp521r1": MARGINAL, "ECP_521": MARGINAL,
    "MODP_4096": VULNERABLE, "MODP_2048": VULNERABLE,
    "MODP_1536": BROKEN, "MODP_1024": BROKEN,
    # Ibridi classico+PQ — SAFE (resistenti a HNDL/SHOR se il componente
    # PQ regge, resistenti a Shor almeno quanto il componente classico)
    "mlkem768x25519": SAFE, "mlkem768x25519-sha256": SAFE,
    "mlkem1024x25519": SAFE, "mlkem1024x25519-sha256": SAFE,
    "sntrup761x25519": SAFE, "sntrup761x25519-sha512": SAFE,
    "X25519MLKEM768": SAFE, "X25519MLKEM1024": SAFE,
    "X25519Kyber768Draft00": SAFE,
    "P256MLKEM768": SAFE, "P384MLKEM1024": SAFE,
    "KYBER_L3": SAFE, "KYBER_L5": SAFE,
    "BIKE_L3": SAFE, "HQC_L3": SAFE,
}

# ── CIPHER: algoritmo simmetrico + lunghezza chiave — minacciato da Grover, non da Shor ──
def _cipher_level(enc: str | None, bits: int | None) -> str:
    if enc is None:
        return UNKNOWN
    enc_u = enc.upper()
    enc_norm = enc_u.replace("-", "").replace("_", "").replace("@", "")
    # ChaCha20-Poly1305 ha chiave 256-bit implicita per design (RFC 8439):
    # non ha un campo bits separato nelle stringhe OpenSSH/IKEv2.
    # Classificato SAFE al livello GROVER — equivalente ad AES-256.
    if "CHACHA20" in enc_norm:
        return SAFE
    if "AES" in enc_u:
        if bits is None:
            # Tenta di estrarre la lunghezza dalla stringa stessa
            for token in ("256", "128"):
                if token in enc_u:
                    bits = int(token)
                    break
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


# ── HASH: funzioni di hash/PRF/firma — minacciate da Grover (collisione: Shor non si applica) ──
_HASH_TABLE = {
    "SHA384": SAFE, "SHA2_384": SAFE, "SHA512": SAFE, "SHA2_512": SAFE,
    "SHA256": MARGINAL, "SHA2_256": MARGINAL,
    "SHA1": BROKEN, "SHA-1": BROKEN,
    "MD5": BROKEN,
}

# ── AUTH IKE: metodo di autenticazione IKE_AUTH — minacciato da Shor ────────
def _ike_auth_level(auth_method: str | None) -> str:
    """Classifica la robustezza PQC del metodo di autenticazione IKE_AUTH.
    Distinto dal KEX (confidenzialità) e dalla cipher (integrità canale):
    qui si valuta la prova crittografica dell'identità dei peer.
    """
    if auth_method is None:
        return UNKNOWN
    a = auth_method.lower()
    # PQ native (sperimentali su strongSwan)
    if "falcon" in a or "dilithium" in a or "crystals" in a:
        return SAFE
    # ECDSA: vulnerabile a Shor ma meglio di RSA a parità di dimensione
    if "ecdsa" in a:
        return MARGINAL
    # PSK: segreto simmetrico, non vulnerabile a Shor ma non scalabile
    # e non fornisce autenticità individuale — classificato MARGINAL
    if "psk" in a:
        return MARGINAL
    # RSA: vulnerabile a Shor
    if "rsa" in a:
        return VULNERABLE
    # EAP-TLS dipende dal certificato sottostante — di default MARGINAL
    if "eap" in a and "tls" in a:
        return MARGINAL
    # EAP-MSCHAPv2: credenziali deboli, non PKI
    if "mschapv2" in a or "mschap" in a:
        return VULNERABLE
    return UNKNOWN


# ── HOSTKEY: tipo e dimensione della chiave di identità (SSH host key, certificati) ──
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
        kex_level = NA  # ripresa PSK-only: nessun KEX in questo handshake

    assessment = {
        "KEX": _dim(kex_level, "HNDL/SHOR"),
        "CIPHER": _dim(_cipher_level(cipher, enc_bits), "GROVER"),
        "MAC": _dim(SAFE if "GCM" in cipher or "POLY1305" in cipher else UNKNOWN, "GROVER"),
        "HOSTKEY": _dim(UNKNOWN, "HNDL/SHOR"),  # richiede il certificato correlato — vedi correlate.py
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
    auth_level = _ike_auth_level(rec.get("auth_method", {}).get("local") if isinstance(rec.get("auth_method"), dict) else None)
    # MAC: se la cifratura è AEAD (GCM/CCM), l'integrità è intrinseca alla
    # cifratura stessa — nessun campo ike_integ separato (vedi
    # ipsec_parser._parse_ike_proposal: 3 segmenti anziché 4). In quel
    # caso SAFE segue direttamente dalla cifratura AEAD, non da una
    # ricerca testuale di "GCM" nel nome della cifratura (quella ricerca
    # bastava finché ike_enc era sempre valorizzato con un algoritmo AEAD
    # reale, ma con .get("ike_enc", "") su un valore None esplicito
    # restituiva comunque None, non "" — causa diretta dell'AttributeError
    # osservato). Per le cifrature non-AEAD (3DES, AES-CBC), l'integrità è
    # un algoritmo negoziato a parte: va classificato per la sua reale
    # robustezza (stessa _HASH_TABLE già usata per PRF/firme), mai dato
    # per SAFE o lasciato UNKNOWN di default.
    ike_integ = rec.get("ike_integ")
    if ike_integ:
        integ_token = _extract_hash_token(ike_integ)
        mac_level = _HASH_TABLE.get(integ_token, UNKNOWN) if integ_token else UNKNOWN
    else:
        mac_level = SAFE if "GCM" in (rec.get("ike_enc") or "").upper() else UNKNOWN
    assessment = {
        "KEX": _dim(kex_level, "HNDL/SHOR"),
        "CIPHER": _dim(_cipher_level(rec.get("ike_enc"), rec.get("ike_enc_bits")), "GROVER"),
        "MAC": _dim(mac_level, "GROVER"),
        "HOSTKEY": _dim(auth_level, "HNDL/SHOR"),  # prova crittografica dell'identità IKE_AUTH
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