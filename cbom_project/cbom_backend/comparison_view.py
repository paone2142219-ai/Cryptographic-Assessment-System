# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# comparison_view.py — complete Expected/Observed comparison for the operator
#
# Complementary to drift_engine.py, not an alternative: that one writes
# VIOLATES (the derived artifact, for alerting and aggregate queries —
# "which critical violations exist right now across the whole
# infrastructure"); this one returns EVERY evaluated dimension, not only
# the deviations — the complete picture a CISO reads to understand the
# posture, not only its problems. Both come from the very same
# comparators (comparators.py) and the very same graph read query
# (fetch_usecase_rows, below — imported by drift_engine.py, not
# duplicated): one computation, two representations.
# =====================================================================
from __future__ import annotations

from neo4j import Driver, ManagedTransaction

import comparators as comp

# Query shared with drift_engine._analyze_usecase_tx — same shape, same
# data origin. Kept here, imported by drift_engine.py, because
# comparison_view.py is conceptually "the read side" of the same
# Expected/Observed relationship that drift_engine writes.
_FETCH_QUERY = """
MATCH (exp:Expected {use_case: $usecase_name})
MATCH (a:Asset)-[:EXPOSES]->(obs:Observed {use_case: $usecase_name})
OPTIONAL MATCH (exp)-[:HAS_IKE_SA]->(ike_exp:IkeSaExpected)
OPTIONAL MATCH (obs)-[:HAS_IKE_SA]->(ike_obs:IkeSaObserved)
OPTIONAL MATCH (exp)-[:HAS_CHILD_SA]->(child_exp:ChildSaExpected)
OPTIONAL MATCH (obs)-[:HAS_CHILD_SA]->(child_obs:ChildSaObserved)
RETURN a.name AS asset, exp AS expected, obs AS observed,
       ike_exp AS ike_expected, ike_obs AS ike_observed,
       child_exp AS child_expected, child_obs AS child_observed
"""

# For SSH Bastion ProxyJump: a separate query that pairs by ssh_context.
# Not merged with _FETCH_QUERY because standard use cases have no
# ssh_context on their Expected nodes — a WHERE on a missing property
# would exclude valid rows in Neo4j Community Edition.
_FETCH_QUERY_PROXYJUMP = """
MATCH (a:Asset)-[:EXPOSES]->(exp:Expected {use_case: $usecase_name})
WHERE exp.ssh_context IS NOT NULL
MATCH (a)-[:EXPOSES]->(obs:Observed {use_case: $usecase_name})
WHERE obs.ssh_context = exp.ssh_context
RETURN a.name AS asset, exp AS expected, obs AS observed,
       null AS ike_expected, null AS ike_observed,
       null AS child_expected, null AS child_observed
"""


def fetch_usecase_rows(tx: ManagedTransaction, usecase_name: str) -> list[dict]:
    """A single graph read, shared by drift_engine.py (which writes its
    VIOLATES derivative) and by this module (which shows the complete
    picture) — prevents the two reads from returning different states
    because of a query difference nobody noticed.

    For SSH Bastion ProxyJump: _FETCH_QUERY_PROXYJUMP is used, pairing
    Expected and Observed by ssh_context. If there are no ProxyJump rows,
    it falls back to the standard query (behavior unchanged for every
    other use case).
    """
    # Try the ProxyJump query first: it returns rows only if Expected
    # nodes with ssh_context exist (the ProxyJump case). For every other
    # use case it returns an empty list and the standard query is used.
    proxyjump_rows = tx.run(_FETCH_QUERY_PROXYJUMP, usecase_name=usecase_name).data()
    if proxyjump_rows:
        return proxyjump_rows
    return tx.run(_FETCH_QUERY, usecase_name=usecase_name).data()


# Mirrored by FINDING_ATTRIBUTE_LABELS / FINDING_SCOPE_LABELS in app.js
# (the Findings tab uses the same vocabulary as the Comparison tab).
_LABELS = {
    "protocol_version": "Protocol version",
    "kex": "Key exchange (KEX)",
    "cipher": "Encryption",
    "mac": "Integrity (MAC)",
    "host_key": "Host/identity key",
    "has_pfs": "Perfect Forward Secrecy",
    "auth_method": "Authentication method",
    "dh_group": "DH group (data plane)",
    "pfs_capable": "PFS configured",
    "rekey_time_seconds": "Rekey time (s)",
    "lifetime_seconds": "Child SA lifetime (s)",
    "pq_readiness": "PQC posture",
}

_SCOPE_LABELS = {
    "generic": "Profile",
    "ike_sa": "IKE SA (control channel)",
    "child_sa": "Child SA (data channel / ESP)",
}


def _evaluate_scope(dimensions: dict, expected: dict, observed: dict, scope: str) -> list[dict]:
    rows = []
    for attribute, compare_fn in dimensions.items():
        result = compare_fn(expected, observed)
        rows.append({
            "scope": scope,
            "scope_label": _SCOPE_LABELS[scope],
            "attribute": attribute,
            "label": _LABELS.get(attribute, attribute),
            **result.to_dict(),
        })
    return rows


def build_comparison_view(driver: Driver, usecase_name: str) -> dict:
    """Entry point: returns, for each asset of the use case, the complete
    Parameter / Configured / Observed / Status table — each row evaluated
    atomically by its own dedicated comparator, never a single criterion
    applied to everything."""
    with driver.session() as session:
        rows = session.execute_read(fetch_usecase_rows, usecase_name)

    assets_out = []
    for row in rows:
        expected = dict(row["expected"])
        observed = dict(row["observed"])
        # The generic profile does not apply to IPsec use cases: the
        # CryptoProfile:Observed anchor for IPSEC_IKE never carries kex/
        # cipher/mac/host_key (they live in the IKE SA/Child SA
        # sub-profiles, by construction — see
        # cbom_loader._write_ipsec_observed_tx). Without this exclusion,
        # every row of the generic profile was ALWAYS not_comparable for an
        # IPsec use case: pure noise, never real information, and visually
        # indistinguishable from a real attribution problem — it had been
        # mistaken for a bug.
        parameters = []
        if observed.get("protocol") != "IPSEC_IKE":
            parameters = _evaluate_scope(
                comp.dimensions_for_protocol(observed.get("protocol")), expected, observed, "generic"
            )

        if row["ike_expected"] is not None and row["ike_observed"] is not None:
            parameters += _evaluate_scope(
                comp.IKE_SA_DIMENSIONS, dict(row["ike_expected"]), dict(row["ike_observed"]), "ike_sa"
            )
        if row["child_expected"] is not None and row["child_observed"] is not None:
            parameters += _evaluate_scope(
                comp.CHILD_SA_DIMENSIONS, dict(row["child_expected"]), dict(row["child_observed"]), "child_sa"
            )

        entry = {"asset": row["asset"], "parameters": parameters}
        # Propagate ssh_context only when it is 2 (ProxyJump hop towards the
        # final target). ssh_context=1 is written on every SSH record, even
        # for standard use cases (SFTP Backup, SFTP DMZ...) — propagating it
        # would enable dual-table mode in the frontend for those cases too,
        # producing duplicates. The frontend uses the presence of at least
        # one asset with ssh_context=2 to identify a ProxyJump.
        # Propagated only for SSH Bastion Access (ProxyJump), identified by
        # the use-case name — not by the value on the Observed node, which
        # could be a leftover of earlier ingests on other SSH use cases.
        ctx = dict(row["observed"]).get("ssh_context")
        if ctx is not None and ctx == 2 and "bastion" in usecase_name.lower():
            entry["ssh_context"] = ctx
        assets_out.append(entry)

    return {"usecase": usecase_name, "assets": assets_out}
