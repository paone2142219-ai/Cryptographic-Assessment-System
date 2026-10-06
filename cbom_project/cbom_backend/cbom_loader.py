# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# cbom_loader.py — from cbom.json (pipeline_cbom.py) to :Observed nodes
#
# Attribution point: a CBOM record carries IP/hostname (via asset_hint,
# if present — see pipeline_cbom/asset_inventory.py) but NEVER a use
# case — we decided this explicitly in an earlier phase of the project,
# for the same reason asset_hint never writes an application role: a
# hostname is a fact, a use case is an attribution that depends on a
# policy declared elsewhere.
#
# That policy elsewhere is already in the graph: the operator, in the
# GUI, has already associated each Asset with a use case through
# (Asset)-[:HOSTS]->(Service)-[:SERVES]->(UseCase). This loader does NOT
# introduce a new attribution logic — it queries the one already
# declared, and writes the observed profile only for the assets the
# graph already knows. An asset observed in the traffic but never
# declared in the GUI is explicitly ignored (with a count in the log),
# not guessed.
# =====================================================================
from __future__ import annotations

import logging
from neo4j import Driver, ManagedTransaction

from schema import ObservedCryptoProfile, IkeSaCryptoProfile, ChildSaCryptoProfile
from crypto_levels import kex_pq_posture, POSTURE_CLASSICAL, POSTURE_HYBRID, POSTURE_NATIVE
import quantum_risk
from graph_writer import refresh_observed_quantum_risk_tx

log = logging.getLogger("cbom_loader")

# ─── Observed labels that must match the GUI vocabulary EXACTLY ──────────
# These strings are compared by comparators.cmp_set_membership against the
# values the operator selects in the GUI (data.js). Set membership is an
# exact string comparison: any drift between the two sides turns a
# genuine match into a false DEVIATION. Keep them byte-for-byte identical
# to the corresponding data.js options.
SSH_AUTH_PUBLIC_KEY = "Public key"                       # data.js: user_auth / auth → "Public key"
TLS_AUTH_CLIENT_CERT = "Client certificate (mTLS)"       # data.js: syslog_tls client_auth → "Client certificate (mTLS)"
IKE_AUTH_PSK = "PSK (Pre-Shared Key)"                    # data.js: IPsec auth_method → "PSK (Pre-Shared Key)"
# IKE certificate authentication is NOT compared by exact string but through
# comparators._normalize_ike_auth (categories psk / pubkey_ecdsa / eap_tls /
# ...), so this label only needs to normalize to the intended category.
IKE_AUTH_PUBKEY = "X.509 certificates (EAP-TLS)"

# ─── Observed post-quantum posture ───────────────────────────────────────
# Derived by crypto_levels.kex_pq_posture() from the observed key exchange
# ONLY — the very same function graph_writer applies to the Expected kex,
# on the very same field. No local marker lists here any more: a second
# copy of the rules is exactly how the two sides drifted apart before
# (the old version read kex+cipher+host key on this side and every GUI
# field on the other).


# Translates the observed protocol (as reported in cbom.json) into the
# same family used by uc.protoFamily in data.js — it is the key of the
# filter in _find_usecases_for_asset(), not a separate detail.
_PROTOCOL_TO_FAMILY = {
    "TLS": "tls",
    "SSH": "ssh",
    "IPSEC_IKE": "ipsec",
}


# ─── Extraction: from a raw CBOM record to a normalized profile ──────────
# Each protocol carries different fields (see pipeline_cbom/parsers/*.py)
# — this function is the single point that brings them back to the same
# shape (kex/cipher/mac/host_key/auth_method), the same one traversed by
# crypto_levels.py for classification.

def _extract_profile(rec: dict) -> ObservedCryptoProfile | None:
    proto = rec.get("protocol")

    if proto == "TLS":
        cert = rec.get("certificate") or {}
        key_type = cert.get("key_type")
        key_length = cert.get("key_length")
        # hostkey_level() looks for a bit count in the text to classify
        # (256/384/521 for ECDSA, 2048/3072/4096 for RSA): "ecdsa" alone
        # does not carry it, "ecdsa-256" does. Before this fix every TLS
        # certificate always classified as UNKNOWN, regardless of how
        # robust it really was.
        host_key_combined = f"{key_type}-{key_length}" if key_type and key_length else key_type
        # Why it is never an assumption: cert_observation_method is already
        # in cbom.json, produced by tls_parser.py by observing the REAL
        # session — if it says "not_observable_tls13_encrypted_certificate",
        # it is because THIS session negotiated TLS 1.3, not because the
        # use case always does.
        unavailable_reason = None
        if not host_key_combined:
            method = rec.get("cert_observation_method")
            if method and method != "exact_fingerprint_match":
                unavailable_reason = method
        # auth_method for TLS: Zeek never carries application-level
        # information (bearer tokens, HTTP headers) — the only really
        # observable signal is whether the CLIENT presented a certificate
        # (non-empty client_cert_chain_fps), which proves mTLS actually
        # happened. "Bearer token" and "None" remain indistinguishable
        # from this source: never inferred, the field stays None in those
        # cases, not a guessed value.
        client_certs = rec.get("client_cert_chain_fps") or []
        tls_auth_method = TLS_AUTH_CLIENT_CERT if client_certs else None
        pq_tls = kex_pq_posture(rec.get("curve"))
        return ObservedCryptoProfile(
            protocol="TLS",
            protocol_version=rec.get("tls_version"),
            kex=rec.get("curve"),
            cipher=rec.get("cipher"),
            mac=rec.get("cipher"),
            host_key=host_key_combined,
            host_key_unavailable_reason=unavailable_reason,
            auth_method=tls_auth_method,
            has_pfs=rec.get("has_pfs"),
            pq_readiness=pq_tls,
            sensor_id=rec.get("sensor_id"),
            ts=rec.get("ts"),
            uid=rec.get("uid"),
        )

    if proto == "SSH":
        ssh_ver = rec.get("ssh_version")
        cipher_alg = rec.get("cipher_alg") or ""
        pq_ssh = kex_pq_posture(rec.get("kex_alg"))

        # When the cipher is AEAD (ChaCha20-Poly1305, AES-GCM), OpenSSH
        # ignores the MAC negotiated during KEX — Poly1305/GHASH are already
        # built into the primitive (RFC 4253 §6.4: "MUST NOT be used").
        # Zeek records it anyway from the handshake, but writing it to Neo4j
        # would produce a meaningless comparison with the Expected MAC.
        # We write None to explicitly signal that it does not apply.
        cipher_is_aead = any(m in cipher_alg.lower()
                             for m in ("gcm", "poly1305", "chacha20"))
        mac_observed = None if cipher_is_aead else rec.get("mac_alg")

        return ObservedCryptoProfile(
            protocol="SSH",
            protocol_version=f"SSHv{ssh_ver}" if ssh_ver else None,
            kex=rec.get("kex_alg"),
            cipher=cipher_alg or None,
            mac=mac_observed,
            host_key=rec.get("host_key_alg"),
            auth_method=SSH_AUTH_PUBLIC_KEY if rec.get("auth_success") else None,
            pq_readiness=pq_ssh,
            sensor_id=rec.get("sensor_id"),
            ts=rec.get("ts"),
            uid=rec.get("uid"),
        )

    return None


# ─── IPsec: two distinct extractors, not one that flattens ───────────────
# Rationale, confirmed by a real bug found in production: a single profile
# forced choosing ONE "cipher" value, which ended up confusing the IKE
# encryption (control channel) with the ESP one (data channel) — apples
# and oranges in the comparison with the Expected, which declares them
# separately right from the GUI (§ vpn_road_warrior / vpn_site_to_site in
# data.js: "Phase 1 encryption (IKE)" vs "ESP encryption (data plane)").

def _extract_ike_sa_profile(rec: dict) -> IkeSaCryptoProfile:
    auth = rec.get("auth_method") or {}
    auth_label = None
    mutual = None
    if auth.get("local") and auth.get("remote"):
        # Both sides with the same declared method — this does not
        # cryptographically prove mutual authentication (that requires
        # observing the IKE_AUTH outcome), but it is the most direct
        # signal available from this source.
        mutual = auth.get("local") == auth.get("remote")
    if auth.get("local") == "psk" or auth.get("remote") == "psk":
        auth_label = IKE_AUTH_PSK
    elif auth.get("local") == "pubkey" or auth.get("remote") == "pubkey":
        auth_label = IKE_AUTH_PUBKEY

    # IKE key exchange = the IKE_SA_INIT group plus any additional key
    # exchanges (RFC 9370, e.g. "KE1_ML_KEM_768" in swanctl --list-sas),
    # joined as "ECP_384+ML_KEM_768" — the same composite notation the GUI
    # uses for its hybrid IKE options, so both sides classify the same kind
    # of string. With a single classical group this is just "ECP_384".
    ike_kex = "+".join(
        g for g in [rec.get("ike_group"), *(rec.get("ike_additional_ke") or [])] if g
    ) or None
    pq_ike = kex_pq_posture(ike_kex)
    return IkeSaCryptoProfile(
        protocol_version="IKEv2",
        cipher=f"{rec.get('ike_enc')}-{rec.get('ike_enc_bits')}" if rec.get("ike_enc") else None,
        mac=rec.get("ike_prf"),
        kex=ike_kex,
        auth_method=auth_label,
        mutual_auth=mutual,
        rekey_time_seconds=rec.get("ike_rekey_time_seconds"),
        pq_readiness=pq_ike,
        sensor_id=rec.get("sensor_id"),
        ts=rec.get("ts"),
        uid=rec.get("ike_uid"),
    )


def _extract_child_sa_profile(rec: dict) -> ChildSaCryptoProfile | None:
    """None if no Child SA is known yet in this sample — a legitimate
    state (not an error), never forced into an empty profile."""
    child_sas = rec.get("child_sas") or []
    if not child_sas:
        return None
    esp = child_sas[0]
    return ChildSaCryptoProfile(
        cipher=f"{esp.get('esp_enc')}-{esp.get('esp_enc_bits')}" if esp.get("esp_enc") else None,
        # esp_group: never present on the very first Child SA by protocol
        # construction (IKE_AUTH carries no KE payload) — absent here does
        # not mean "no data", it means "not observable yet".
        dh_group=esp.get("esp_group"),
        pfs_capable=esp.get("declared_pfs_capable"),
        pfs_observed=esp.get("has_pfs"),
        lifetime_seconds=rec.get("child_rekey_time_seconds"),
        mode="tunnel",  # the only mode used in the lab
        sensor_id=rec.get("sensor_id"),
        ts=rec.get("ts"),
        uid=esp.get("child_uid"),
    )


def _hostnames_involved(rec: dict) -> list[str]:
    """Extracts the involved hostnames from asset_hint — never raw IPs:
    if asset_hint is missing (no match in the external inventory), the
    record cannot be attributed to any declared Asset, full stop."""
    hint = rec.get("asset_hint") or {}
    names = [hint.get("src_hostname"), hint.get("dst_hostname"),
             hint.get("local_hostname"), hint.get("remote_hostname")]
    # Road-warrior pool hints carry a descriptive suffix in parentheses
    # ("clientext (road warrior, admin pool — virtual IP)") that does not
    # match the Asset node name — normalize by taking only the first token.
    cleaned = []
    for n in names:
        if n:
            cleaned.append(n.split(" (")[0].strip())
    return list(dict.fromkeys(cleaned))  # dedup preserving order


def load_cbom(driver: Driver, cbom: dict) -> dict:
    """Entry point: receives the already deserialized dict of cbom.json,
    extracts a profile for every connection with a recognizable
    asset_hint, and writes it on each Asset already known to the graph,
    for each use case that Asset serves according to the association
    already declared in the GUI."""
    connections = cbom.get("connections", [])
    written, skipped_no_asset, skipped_no_usecase, skipped_no_profile = 0, 0, 0, 0
    # Observed key-exchange posture of EVERY session, per use case — the
    # input of the observed HNDL exposure (see quantum_risk.py). Counted
    # once per (session, use case): a session whose two endpoints are both
    # assets of the same use case is still one recorded transfer. Built
    # here, over the whole cbom.json, because the :Observed node keeps only
    # the latest session per asset and would hide a classical session
    # followed by a hybrid one.
    kex_sessions: dict[str, list[str]] = {}

    with driver.session() as session:
        for rec in connections:
            hostnames = _hostnames_involved(rec)
            if not hostnames:
                skipped_no_asset += 1
                continue

            if rec.get("protocol") == "IPSEC_IKE":
                # Dedicated branch: two distinct profiles (IKE SA, Child SA),
                # never flattened into one — see comment above
                # _extract_ike_sa_profile.
                ike_profile = _extract_ike_sa_profile(rec)
                child_profile = _extract_child_sa_profile(rec)
                attributed: set[str] = set()
                for hostname in hostnames:
                    use_cases = session.execute_read(_find_usecases_for_asset, hostname, "IPSEC_IKE")
                    if not use_cases:
                        skipped_no_usecase += 1
                        continue
                    for uc_name in use_cases:
                        session.execute_write(
                            _write_ipsec_observed_tx, hostname, uc_name, ike_profile, child_profile
                        )
                        written += 1 + (1 if child_profile is not None else 0)
                        attributed.add(uc_name)
                for uc_name in attributed:
                    kex_sessions.setdefault(uc_name, []).append(ike_profile.pq_readiness)
                continue

            profile = _extract_profile(rec)
            if profile is None:
                skipped_no_profile += 1
                continue

            attributed = set()
            for hostname in hostnames:
                use_cases = session.execute_read(_find_usecases_for_asset, hostname, rec.get("protocol"))
                if not use_cases:
                    skipped_no_usecase += 1
                    continue
                # Raw ssh_context from the record (1 or 2 for SSH, None for other protocols).
                # Annotated by correlate_ssh_proxyjump — it is 1 for standard SSH too.
                ssh_ctx_raw = rec.get("ssh_context") if rec.get("protocol") == "SSH" else None

                for uc_name in use_cases:
                    # Query the graph: the use case is ProxyJump only if the
                    # Expected for this asset has a declared ssh_context (1 or 2).
                    # For standard SSH (SFTP Backup, SFTP DMZ, etc.) expected_ctx is
                    # None — in that case ssh_context is NOT written on the Observed,
                    # preventing comparison_view from propagating it to the frontend
                    # and wrongly enabling dual-table mode for non-ProxyJump use cases.
                    if ssh_ctx_raw is not None:
                        expected_ctx = session.execute_read(
                            _expected_ssh_context_for, hostname, uc_name
                        )
                        # Discard the record if the context does not match the expected one
                        if expected_ctx is not None and expected_ctx != ssh_ctx_raw:
                            skipped_no_usecase += 1
                            continue
                        # Pass ssh_context to the Observed only for ProxyJump cases
                        ssh_ctx = ssh_ctx_raw if expected_ctx is not None else None
                    else:
                        ssh_ctx = None

                    session.execute_write(
                        _write_observed_tx, hostname, uc_name, profile, ssh_ctx
                    )
                    written += 1
                    attributed.add(uc_name)
            for uc_name in attributed:
                kex_sessions.setdefault(uc_name, []).append(profile.pq_readiness)

        # Observed KEX summary + observed HNDL exposure, for EVERY use case
        # in the graph: pipeline_cbom re-reads the whole shared/ folder on
        # each run, so a use case with no attributed session in this ingest
        # really has no observed traffic — its summary is reset and its
        # observed exposure becomes "not evaluable" (None), never a stale
        # value from a previous ingest nor a false "no risk".
        kex_summary = {}
        for uc_name in session.execute_read(_all_usecase_names):
            postures = kex_sessions.get(uc_name, [])
            counts = {POSTURE_CLASSICAL: postures.count(POSTURE_CLASSICAL),
                      POSTURE_HYBRID: postures.count(POSTURE_HYBRID),
                      POSTURE_NATIVE: postures.count(POSTURE_NATIVE)}
            worst = quantum_risk.worst_posture(postures)
            session.execute_write(_write_observed_kex_summary_tx, uc_name, worst, counts)
            kex_summary[uc_name] = {"sessions": len(postures), "worst": worst, **counts}

    log.info(
        f"cbom_loader: {written} Observed profiles written, "
        f"{skipped_no_profile} records without an extractor for their protocol, "
        f"{skipped_no_asset} without asset_hint, "
        f"{skipped_no_usecase} on assets not associated with any use case in the GUI"
    )
    return {
        "observed_written": written,
        "skipped_no_profile": skipped_no_profile,
        "skipped_no_asset_hint": skipped_no_asset,
        "skipped_asset_without_usecase": skipped_no_usecase,
        "observed_kex_summary": kex_summary,
    }


def _all_usecase_names(tx: ManagedTransaction) -> list[str]:
    return [r["name"] for r in tx.run("MATCH (u:UseCase) RETURN u.name AS name")]


def _write_observed_kex_summary_tx(tx: ManagedTransaction, usecase_name: str,
                                   worst: str | None, counts: dict[str, int]) -> None:
    """Stores the observed key-exchange summary on the UseCase node (never
    on :Observed — it aggregates many sessions, and shelf time, its partner
    in the HNDL heuristic, is a use-case attribute too), then recomputes the
    observed exposure with the shared heuristic in the same transaction."""
    tx.run(
        """
        MATCH (u:UseCase {name: $name})
        SET u.observed_kex_posture_worst = $worst,
            u.observed_kex_sessions_classical = $c,
            u.observed_kex_sessions_hybrid = $h,
            u.observed_kex_sessions_native = $n
        """,
        name=usecase_name, worst=worst,
        c=counts[POSTURE_CLASSICAL], h=counts[POSTURE_HYBRID], n=counts[POSTURE_NATIVE],
    )
    refresh_observed_quantum_risk_tx(tx, usecase_name)


def _expected_ssh_context_for(tx: ManagedTransaction, hostname: str, usecase_name: str) -> int | None:
    """Returns the ssh_context required by the Expected node for this
    (hostname, usecase_name) pair, or None if the Expected has no
    ssh_context (standard SSH use case, not ProxyJump).

    Used by load_cbom to prevent an SSH record with ssh_context=1
    (e.g. appserver → backupsrv, a standalone session) from being written
    as Observed for a ProxyJump use case where appserver is expected as
    ctx2 — a wrong pairing by construction.
    """
    result = tx.run(
        """
        MATCH (a:Asset {name: $hostname})-[:EXPOSES]->(exp:Expected {use_case: $usecase_name})
        WHERE exp.ssh_context IS NOT NULL
        RETURN exp.ssh_context AS ctx
        LIMIT 1
        """,
        hostname=hostname, usecase_name=usecase_name,
    ).single()
    return result["ctx"] if result else None


def _find_usecases_for_asset(tx: ManagedTransaction, hostname: str, protocol: str) -> list[str]:
    """Returns only the use cases whose Service has the same protocol
    family as the observed record — no longer every use case the hostname
    is generically associated with.

    The bug this filter fixes: clientext is declared as an asset for
    "VPN Road Warrior" (IPsec) but also generates SSH traffic (through
    the tunnel, towards the bastion) — without this filter, the SSH
    record was also attributed to "VPN Road Warrior" just because the
    asset name matched, producing a comparison between an Expected
    profile designed for IPsec and an SSH Observed profile."""
    family = _PROTOCOL_TO_FAMILY.get(protocol)
    if family is None:
        # Observed protocol with no known family (should not happen with
        # the current extractors, but if it does, do not attribute blindly
        # — better no match than a wrong one).
        return []
    query = """
    MATCH (a:Asset {name: $hostname})-[:HOSTS]->(svc:Service)-[:SERVES]->(use:UseCase)
    WHERE svc.protocol_family = $family
    RETURN DISTINCT use.name AS usecase_name
    """
    return [r["usecase_name"] for r in tx.run(query, hostname=hostname, family=family)]


def _write_observed_tx(tx: ManagedTransaction, hostname: str, usecase_name: str,
                        profile: ObservedCryptoProfile,
                        ssh_context: int | None = None) -> None:
    # For SSH ProxyJump: observed_key includes the context (::ctx1 or ::ctx2)
    # so that drift_engine pairs each Observed with the correct per-hop Expected.
    if ssh_context is not None:
        observed_key = f"{hostname}::{usecase_name}::ctx{ssh_context}"
    else:
        observed_key = f"{hostname}::{usecase_name}"

    props = profile.to_neo4j_props()
    if ssh_context is not None:
        props["ssh_context"] = ssh_context

    query = """
    MATCH (a:Asset {name: $hostname})
    MERGE (obs:CryptoProfile:Observed {observed_key: $observed_key})
      SET obs += $props,
          obs.use_case = $usecase_name,
          obs.asset = $hostname
    MERGE (a)-[:EXPOSES]->(obs)
    """
    tx.run(query, hostname=hostname, observed_key=observed_key,
           usecase_name=usecase_name, props=props)


def _write_ipsec_observed_tx(tx: ManagedTransaction, hostname: str, usecase_name: str,
                              ike_profile: IkeSaCryptoProfile,
                              child_profile: ChildSaCryptoProfile | None) -> None:
    """Writes the 'anchor' Observed node (same shape as _write_observed_tx,
    for consistency with EXPOSES and with drift_engine.py's lookup) plus
    the two sub-profiles attached through HAS_IKE_SA / HAS_CHILD_SA — the
    same structure, on the observed side, already written on the Expected
    side by graph_writer._write_ipsec_subprofiles_tx."""
    observed_key = f"{hostname}::{usecase_name}"

    tx.run(
        """
        MATCH (a:Asset {name: $hostname})
        MERGE (obs:CryptoProfile:Observed {observed_key: $observed_key})
          SET obs.use_case = $usecase_name,
              obs.asset = $hostname,
              obs.protocol = "IPSEC_IKE"
        MERGE (a)-[:EXPOSES]->(obs)
        MERGE (ike:IkeSaProfile:IkeSaObserved {observed_key: $observed_key})
          SET ike += $ike_props
        MERGE (obs)-[:HAS_IKE_SA]->(ike)
        """,
        hostname=hostname, observed_key=observed_key, usecase_name=usecase_name,
        ike_props=ike_profile.to_neo4j_props(),
    )

    if child_profile is not None:
        tx.run(
            """
            MATCH (obs:CryptoProfile:Observed {observed_key: $observed_key})
            MERGE (child:ChildSaProfile:ChildSaObserved {observed_key: $observed_key})
              SET child += $child_props
            MERGE (obs)-[:HAS_CHILD_SA]->(child)
            """,
            observed_key=observed_key, child_props=child_profile.to_neo4j_props(),
        )
