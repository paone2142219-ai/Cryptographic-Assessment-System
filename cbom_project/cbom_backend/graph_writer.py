# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# graph_writer.py — Translation engine towards the native graph
#
# This is the module the professor would identify as "the conversion
# engine": it receives a UseCaseInput already validated by Pydantic (=
# compliant with the domain vocabulary) and translates it into
# parametric Cypher transactions, following EXACTLY the relationship
# schema defined in the reference Cypher file:
#
#   (:UseCase) -[:REQUIRES]-> (:Policy)
#   (:Service) -[:SERVES {confidence}]-> (:UseCase)
#   (:Asset)   -[:HOSTS]-> (:Service)
#   (:Asset)   -[:EXPOSES]-> (:CryptoProfile:Expected)
#
# Every write uses MERGE (idempotent: re-running the same write does not
# duplicate nodes/relationships) and parametric queries ($param, never
# concatenated f-strings) to prevent Cypher injection and let Neo4j reuse
# the query plan.
#
# UPDATE — Lifecycle & Data Governance: the UseCase node now also
# receives the harvest-now-decrypt-later exposure on BOTH sides —
# quantum_risk_expected_flag/rationale (shelf time × expected key-exchange
# posture, computed here on save) and quantum_risk_observed_flag/rationale
# (shelf time × worst observed key-exchange posture, computed by
# cbom_loader on ingest and refreshed here when the shelf time changes),
# with one shared heuristic in quantum_risk.py
# — and governance_risk_level/rationale, derived by
# _compute_governance_risk() from suggested_criticality and
# data_sensitivity (fixed matrix, orthogonal to the technical severity of
# VIOLATES: see the function for why they are not merged into a single
# number). The new data_sensitivity and pq_readiness fields of the
# Expected profile flow automatically into expected_props through
# ExpectedCryptoProfile.to_neo4j_props(), with no further change needed
# to the "SET exp += $expected_props" clause.
# =====================================================================

from neo4j import Driver, ManagedTransaction

import quantum_risk
from crypto_levels import (
    kex_pq_posture, POSTURE_CLASSICAL, POSTURE_HYBRID, POSTURE_NATIVE,
)
from schema import PQReadiness, UseCaseInput


# ─── QUANTUM RISK (HNDL) — expected side ─────────────────────────────────
# The heuristic itself (Mosca simplification, threshold, rationale) lives in
# quantum_risk.py and is shared with the observed side: see that module for
# why shelf time is a use-case attribute and why the observed posture is
# the worst over all sessions.


def _compute_quantum_risk(uc: UseCaseInput) -> dict:
    """
    Expected HNDL exposure: shelf_time_days (UseCase) × pq_readiness of the
    expected key exchange (already recomputed by
    _derive_expected_pq_postures). Returns the properties to write on the
    UseCase node; informational only, it never blocks the write.
    """
    pq = uc.expected.pq_readiness.value if uc.expected.pq_readiness else None
    r = quantum_risk.assess(uc.shelf_time_days, pq, quantum_risk.EXPECTED)
    return {
        "quantum_risk_expected_flag": r["flag"],
        "quantum_risk_expected_rationale": r["rationale"],
    }


def refresh_observed_quantum_risk_tx(tx: ManagedTransaction, usecase_name: str) -> None:
    """
    Recomputes the OBSERVED HNDL exposure of a use case from what is already
    stored on its UseCase node: the declared shelf time and the observed
    key-exchange summary written by cbom_loader at the last ingest
    (observed_kex_posture_worst + per-posture session counts). Called on
    every policy save — the shelf time may have changed while the observed
    traffic did not — and by cbom_loader after an ingest. Never reads the
    :Observed nodes: they keep only the latest session per asset, while the
    summary covers every session of the last ingest.
    """
    rec = tx.run(
        """
        MATCH (u:UseCase {name: $name})
        RETURN u.shelf_time_days AS shelf,
               u.observed_kex_posture_worst AS worst,
               u.observed_kex_sessions_classical AS c,
               u.observed_kex_sessions_hybrid AS h,
               u.observed_kex_sessions_native AS n
        """,
        name=usecase_name,
    ).single()
    if rec is None:
        return
    sessions = {POSTURE_CLASSICAL: rec["c"] or 0, POSTURE_HYBRID: rec["h"] or 0,
                POSTURE_NATIVE: rec["n"] or 0}
    r = quantum_risk.assess(rec["shelf"], rec["worst"], quantum_risk.OBSERVED, sessions)
    tx.run(
        """
        MATCH (u:UseCase {name: $name})
        SET u.quantum_risk_observed_flag = $flag,
            u.quantum_risk_observed_rationale = $rationale
        """,
        name=usecase_name, flag=r["flag"], rationale=r["rationale"],
    )


def _derive_expected_pq_postures(uc: UseCaseInput) -> None:
    """
    Recomputes pq_readiness on every Expected profile of the use case from
    its expected key exchange, with crypto_levels.kex_pq_posture() — the
    SAME function cbom_loader applies to the observed kex. Any pq_readiness
    sent by the GUI is overwritten: the GUI value is only a live preview
    (kexPQPosture() in app.js), the graph never trusts a posture it did not
    derive itself. This is what makes the Expected/Observed comparison of
    the posture symmetric: same function, same field, same side of the
    HTTP boundary.

    Which kex, per protocol family (identical to KEX_FIELD_BY_FAMILY in
    app.js):
      - TLS / SSH : expected.kex  (GUI "curve" / "kex")
      - IPsec     : ike_sa.kex    (GUI "dh1"; the generic Expected carries no
                    kex for IPsec) — every Child SA key is derived from the
                    IKE SA key material, so the IKE key exchange is what
                    protects recorded ESP traffic too
      - ProxyJump : expected2.kex for SSH hop #2 (GUI "kex2")
    """
    ike_kex = uc.ike_sa.kex if uc.ike_sa is not None else None
    uc.expected.pq_readiness = PQReadiness(kex_pq_posture(uc.expected.kex or ike_kex))
    if uc.ike_sa is not None:
        uc.ike_sa.pq_readiness = kex_pq_posture(ike_kex)
    if uc.expected2 is not None:
        uc.expected2.pq_readiness = PQReadiness(kex_pq_posture(uc.expected2.kex))


def _compute_governance_risk(uc: UseCaseInput) -> dict:
    """
    Derives a "context risk" (governance, not technical) from the
    combination of suggested_criticality (UseCase) and data_sensitivity
    (Expected) — orthogonal to the severity of VIOLATES: the latter
    measures HOW FAR the observed primitive deviates from the expected
    one, this one measures HOW MUCH that gap MATTERS given what it
    protects. An identical technical gap weighs differently on a LOW
    context-risk case than on a CRITICAL one — which is why they stay two
    separate axes, never merged into a single number: merging them would
    lose the information that makes this section useful (which technical
    finding deserves remediation priority, not just which one is more
    severe in the abstract).

    Fixed matrix (not a weighted formula): more readable and easier to
    justify cell by cell than a product or an average, which would
    squash or amplify combinations less intuitively at the extremes of
    the scale.
    """
    criticality = uc.suggested_criticality.value
    sensitivity = uc.expected.data_sensitivity.value if uc.expected.data_sensitivity else None

    if sensitivity is None:
        return {
            "governance_risk_level": "UNKNOWN",
            "governance_risk_rationale": (
                "Data sensitivity not declared for this use case: the context "
                "risk cannot be computed. Set data_sensitivity in the Expected "
                "profile (Lifecycle & Data Governance section)."
            ),
        }

    level = _GOVERNANCE_RISK_MATRIX.get((criticality, sensitivity), "UNKNOWN")
    rationale = (
        f"Use-case criticality '{criticality}' combined with sensitivity of the "
        f"transported data '{sensitivity}': context risk {level}. Used to "
        f"prioritize remediation of technical findings on this use case, not "
        f"to change their cryptographic severity."
    )
    return {"governance_risk_level": level, "governance_risk_rationale": rationale}


# Rows = suggested_criticality (UseCase), columns = data_sensitivity
# (Expected) — both keys are the literal enum values in schema.py
# (Criticality, DataSensitivity), not a numeric index: an unforeseen
# combination (e.g. a future value not yet in the table) explicitly
# returns UNKNOWN from _compute_governance_risk above, never an
# optimistic default. Mirrored by GOVERNANCE_RISK_MATRIX in app.js (GUI
# preview only): if the two drift apart it is a bug to fix in both places.
_GOVERNANCE_RISK_MATRIX: dict[tuple[str, str], str] = {
    ("low",    "public"):       "LOW",
    ("low",    "internal"):     "LOW",
    ("low",    "confidential"): "MEDIUM",
    ("low",    "critical"):     "MEDIUM",
    ("medium", "public"):       "LOW",
    ("medium", "internal"):     "MEDIUM",
    ("medium", "confidential"): "MEDIUM",
    ("medium", "critical"):     "HIGH",
    ("high",   "public"):       "MEDIUM",
    ("high",   "internal"):     "MEDIUM",
    ("high",   "confidential"): "HIGH",
    ("high",   "critical"):     "CRITICAL",
}


def _write_bastion_proxyjump_tx(tx: ManagedTransaction, uc: UseCaseInput) -> None:
    """
    Writes the two CryptoProfile:Expected nodes for SSH Bastion ProxyJump,
    one per cryptographic context:

      ctx1 — ClientExt ↔ Bastion (SSH #1)
              Expected identified by: observed_key = "bastion::usecase_name::ctx1"
              Asset EXPOSES: bastion (the SSH #1 terminator)

      ctx2 — ClientExt ↔ AppServer end-to-end (SSH #2)
              Expected identified by: observed_key = "appserver::usecase_name::ctx2"
              Asset EXPOSES: appserver (the SSH #2 terminator)

    The observed_key here is deliberately the same one built by
    cbom_loader._write_observed_tx with ssh_context=1/2, so that the
    _FETCH_QUERY in comparison_view.py pairs Expected and Observed by
    (asset, context) without changes to the query itself.
    """
    if not uc.expected2:
        return  # defensive call, should never happen

    uc_name = uc.name

    # ctx1 — bastion as SSH #1 terminator
    exp1_props = {**uc.expected.to_neo4j_props(), "ssh_context": 1, "use_case": uc_name}
    tx.run(
        """
        MATCH (a:Asset {name: 'bastion'})
        MERGE (exp:CryptoProfile:Expected {observed_key: $key})
          SET exp += $props
        MERGE (a)-[:EXPOSES]->(exp)
        """,
        key=f"bastion::{uc_name}::ctx1",
        props=exp1_props,
    )

    # ctx2 — appserver as SSH #2 terminator (end-to-end)
    exp2_props = {**uc.expected2.to_neo4j_props(), "ssh_context": 2, "use_case": uc_name}
    tx.run(
        """
        MATCH (a:Asset {name: 'appserver'})
        MERGE (exp:CryptoProfile:Expected {observed_key: $key})
          SET exp += $props
        MERGE (a)-[:EXPOSES]->(exp)
        """,
        key=f"appserver::{uc_name}::ctx2",
        props=exp2_props,
    )


def write_usecase(driver: Driver, uc: UseCaseInput, run_drift: bool = True) -> dict:
    """
    Writes a complete use case (UseCase + Policy + Expected + Asset +
    Service + all relationships) in a single atomic transaction.
    If any part fails, the whole write is rolled back (Neo4j's native
    ACID guarantee on the single transaction).

    Note on data_sensitivity/pq_readiness: they are Pydantic enumerations
    (class DataSensitivity(str, Enum)). The Bolt driver requires native
    primitive types, not Enum instances: ExpectedCryptoProfile.to_neo4j_props()
    therefore uses model_dump(mode="json") to guarantee these fields
    arrive as plain strings, just as suggested_criticality is normalized
    explicitly with .value a few lines below.
    """
    _derive_expected_pq_postures(uc)

    with driver.session() as session:
        result = session.execute_write(_write_usecase_tx, uc)
        # IKE SA / Child SA sub-profiles — separate transaction,
        # deliberately: only for IPsec use cases (uc.ike_sa/child_sa not
        # None), never for the others. Keeping it separate from the main
        # transaction avoids weighing down the query shared by all use
        # cases with an optional Cypher block.
        if uc.ike_sa is not None or uc.child_sa is not None:
            session.execute_write(_write_ipsec_subprofiles_tx, uc)
        # For SSH Bastion ProxyJump: writes the two per-context Expected
        # nodes as a separate transaction (same rationale as the IPsec
        # sub-profiles: optional logic kept out of the query shared by all
        # use cases).
        if uc.is_bastion_proxyjump and uc.expected2 is not None:
            session.execute_write(_write_bastion_proxyjump_tx, uc)

        # Observed HNDL exposure: same heuristic, observed posture from the
        # last ingest, CURRENT shelf time — refreshed here because the
        # operator may have just changed the shelf time.
        session.execute_write(refresh_observed_quantum_risk_tx, uc.name)

        # Recompute VIOLATES after every policy update.
        # Prevents findings from going stale if the operator changes the
        # policy without running a new ingest. Optional: can be disabled
        # by passing run_drift=False for callers hitting the endpoint in batch.
        if run_drift:
            from drift_engine import run_drift_analysis
            run_drift_analysis(driver, usecase_name=uc.name)

        return result


def _write_usecase_tx(tx: ManagedTransaction, uc: UseCaseInput) -> dict:
    expected_props = uc.expected.to_neo4j_props()
    q_risk = _compute_quantum_risk(uc)
    governance_risk = _compute_governance_risk(uc)

    query = """
    // --- UseCase -------------------------------------------------
    MERGE (use:UseCase {name: $usecase_name})
      SET use.shelf_time_days = $shelf_time_days,
          use.suggested_criticality = $suggested_criticality,
          use.rationale = $rationale,
          use.quantum_risk_expected_flag = $quantum_risk_expected_flag,
          use.quantum_risk_expected_rationale = $quantum_risk_expected_rationale,
          use.governance_risk_level = $governance_risk_level,
          use.governance_risk_rationale = $governance_risk_rationale

    // --- Policy ----------------------------------------------------
    MERGE (pol:Policy {use_case: $usecase_name})
      SET pol.name = $policy_name,
          pol.description = $policy_description
    MERGE (use)-[:REQUIRES]->(pol)

    // --- Expected CryptoProfile -------------------------------------
    // use_case is the logical MERGE key for the "generic" :Expected node
    // (a standard use case has only one). It is NO LONGER enforced as a
    // uniqueness constraint at database level — see init_schema.py: the
    // SSH Bastion ProxyJump case legitimately writes several :Expected
    // nodes with the same use_case (one per SSH context, distinguished by
    // observed_key, which is unique at schema level).
    MERGE (exp:CryptoProfile:Expected {use_case: $usecase_name})
      SET exp += $expected_props

    // --- Service -----------------------------------------------------
    // service_key is the derived uniqueness key for :Service
    // (Community Edition does not support native composite NODE KEYs).
    MERGE (svc:Service {service_key: $service_key})
      SET svc.name = $service_name,
          svc.protocol = $service_protocol,
          svc.protocol_family = $service_protocol_family
    MERGE (svc)-[:SERVES {confidence: 1.0}]->(use)

    // --- Multiple assets + HOSTS / EXPOSES relationships ---------------
    WITH use, exp, svc
    UNWIND $assets AS asset_data
      MERGE (a:Asset {name: asset_data.name})
        SET a.role = asset_data.role,
            a.zone = asset_data.zone,
            a.criticality = asset_data.criticality,
            a.ip = asset_data.ip,
            a.hostname = asset_data.hostname
      MERGE (a)-[:HOSTS]->(svc)
      MERGE (a)-[:EXPOSES]->(exp)

    RETURN count(DISTINCT a) AS assets_written
    """

    record = tx.run(
        query,
        usecase_name=uc.name,
        shelf_time_days=uc.shelf_time_days,
        suggested_criticality=uc.suggested_criticality.value,
        rationale=uc.rationale,
        quantum_risk_expected_flag=q_risk["quantum_risk_expected_flag"],
        quantum_risk_expected_rationale=q_risk["quantum_risk_expected_rationale"],
        governance_risk_level=governance_risk["governance_risk_level"],
        governance_risk_rationale=governance_risk["governance_risk_rationale"],
        policy_name=uc.policy.name,
        policy_description=uc.policy.description,
        expected_props=expected_props,
        service_key=f"svc_{uc.name.lower().replace(' ', '_')}",
        service_name=uc.service_name,
        service_protocol=uc.service_protocol,
        service_protocol_family=uc.service_protocol_family,
        assets=[
            {
                "name": a.name,
                "role": a.role,
                "zone": a.zone.value,
                "criticality": a.criticality.value,
                "ip": str(a.ip),
                "hostname": a.hostname,
            }
            for a in uc.assets
        ],
    ).single()

    return {
        "status": "ok",
        "usecase": uc.name,
        "assets_written": record["assets_written"],
        "nodes_touched": record["assets_written"] + 3,  # UseCase + Policy + Expected + Service + assets
    }


def _write_ipsec_subprofiles_tx(tx: ManagedTransaction, uc: UseCaseInput) -> None:
    """
    Writes the IkeSaProfile:Expected and ChildSaProfile:Expected
    sub-profiles, attached to the CryptoProfile:Expected node already
    written by _write_usecase_tx through the HAS_IKE_SA / HAS_CHILD_SA
    relationships.

    MERGE on the same use_case key as the parent Expected: a use case has
    only one IkeSaProfile:Expected and one ChildSaProfile:Expected,
    consistent with how CryptoProfile:Expected itself is already modeled
    (a single node per use case, overwritten on every save).
    """
    if uc.ike_sa is not None:
        tx.run(
            """
            MATCH (exp:CryptoProfile:Expected {use_case: $usecase_name})
            MERGE (ike:IkeSaProfile:IkeSaExpected {use_case: $usecase_name})
              SET ike += $ike_props
            MERGE (exp)-[:HAS_IKE_SA]->(ike)
            """,
            usecase_name=uc.name,
            ike_props=uc.ike_sa.to_neo4j_props(),
        )
    if uc.child_sa is not None:
        tx.run(
            """
            MATCH (exp:CryptoProfile:Expected {use_case: $usecase_name})
            MERGE (child:ChildSaProfile:ChildSaExpected {use_case: $usecase_name})
              SET child += $child_props
            MERGE (exp)-[:HAS_CHILD_SA]->(child)
            """,
            usecase_name=uc.name,
            child_props=uc.child_sa.to_neo4j_props(),
        )


def read_usecase_summary(driver: Driver, usecase_name: str) -> dict | None:
    """
    Read function used by the GUI to reload the current state of an
    already saved use case (useful for populating the form at startup).
    """
    with driver.session() as session:
        return session.execute_read(_read_usecase_tx, usecase_name)


def _read_usecase_tx(tx: ManagedTransaction, usecase_name: str) -> dict | None:
    query = """
    MATCH (use:UseCase {name: $usecase_name})
    OPTIONAL MATCH (use)-[:REQUIRES]->(pol:Policy)
    OPTIONAL MATCH (svc:Service)-[:SERVES]->(use)
    OPTIONAL MATCH (a:Asset)-[:HOSTS]->(svc)
    OPTIONAL MATCH (a)-[:EXPOSES]->(exp:Expected {use_case: $usecase_name})
    RETURN use, pol, svc,
           collect(DISTINCT a) AS assets,
           exp
    LIMIT 1
    """
    record = tx.run(query, usecase_name=usecase_name).single()
    if record is None or record["use"] is None:
        return None

    return {
        "usecase": dict(record["use"]),
        "policy": dict(record["pol"]) if record["pol"] else None,
        "service": dict(record["svc"]) if record["svc"] else None,
        "assets": [dict(a) for a in record["assets"]],
        "expected": dict(record["exp"]) if record["exp"] else None,
    }
