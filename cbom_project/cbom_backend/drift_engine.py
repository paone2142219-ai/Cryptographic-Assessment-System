# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# drift_engine.py — Expected/Observed comparison, VIOLATES writing
#
# VIOLATES remains a DERIVED ARTIFACT, useful for alerting and aggregate
# queries ("which critical violations exist right now, across the whole
# infrastructure") — it is no longer the source of truth the operator
# reads directly: that is the complete comparison view
# (comparison_view.py), which shows every dimension, not only the
# deviating ones. Both come from the very same computation — the
# dimension registries in comparators.py — never from two duplicated
# logics that could drift apart.
#
# Every dimension is evaluated atomically by a dedicated function (see
# comparators.TLS_DIMENSIONS / SSH_DIMENSIONS / IKE_SA_DIMENSIONS /
# CHILD_SA_DIMENSIONS, selected by dimensions_for_protocol): an ordinal
# comparator for protocol versions, a tiered one for KEX/cipher/MAC/host
# key, an explicit-direction numeric one for key lengths and rekey time, a
# boolean one for PFS (TLS/IPsec only — SSH does not have it, see the note
# on SSH_DIMENSIONS), a set-membership one for the authentication method —
# never a single criterion forced onto everything.
# =====================================================================
from __future__ import annotations

import logging
from datetime import datetime, timezone
from neo4j import Driver, ManagedTransaction

import comparators as comp
from comparison_view import fetch_usecase_rows

log = logging.getLogger("drift_engine")


def run_drift_analysis(driver: Driver, usecase_name: str | None = None) -> dict:
    """Runs the comparison for a single use case, or for all of them if
    usecase_name is None (e.g. after a bulk ingest of cbom.json that
    touches several use cases at once)."""
    with driver.session() as session:
        names = [usecase_name] if usecase_name else session.execute_read(_all_usecase_names)

        total_violations, total_resolved = 0, 0
        for name in names:
            v, r = session.execute_write(_analyze_usecase_tx, name)
            total_violations += v
            total_resolved += r

    log.info(f"drift_engine: {total_violations} violations written/updated, "
              f"{total_resolved} resolved and removed, across {len(names)} use cases")
    return {"usecases_analyzed": len(names), "violations_written": total_violations,
            "violations_resolved": total_resolved}


def _all_usecase_names(tx: ManagedTransaction) -> list[str]:
    return [r["name"] for r in tx.run("MATCH (u:UseCase) RETURN u.name AS name")]


def _apply_dimensions(tx: ManagedTransaction, dimensions: dict, expected: dict, observed: dict,
                       obs_label: str, obs_key_prop: str, obs_key_val: str,
                       exp_label: str, exp_key_prop: str, exp_key_val: str,
                       attribute_prefix: str) -> tuple[int, int]:
    """Applies every comparator of the registry, and for each DEVIATION
    result writes/updates VIOLATES; for each MATCH it removes any earlier
    VIOLATES (drift resolved). NOT_COMPARABLE neither writes nor removes
    anything — it stays silent, never a false verdict.

    The labels (obs_label/exp_label) are interpolated into the query
    because Cypher does not support parametric labels — they always come
    from a fixed set decided in this same file, never from external
    input: it is not an injection surface."""
    written, resolved = 0, 0
    now = datetime.now(timezone.utc).isoformat()

    for attribute, compare_fn in dimensions.items():
        result = compare_fn(expected, observed)
        full_attribute = f"{attribute_prefix}{attribute}"

        if result.status == comp.DEVIATION:
            tx.run(
                f"""
                MATCH (obs:{obs_label} {{{obs_key_prop}: $obs_key_val}})
                MATCH (exp:{exp_label} {{{exp_key_prop}: $exp_key_val}})
                MERGE (obs)-[v:VIOLATES {{violated_attribute: $attribute}}]->(exp)
                  SET v.observed_value = $obs_val,
                      v.expected_value = $exp_val,
                      v.severity = $severity,
                      v.comparator = $comparator,
                      v.detail = $detail,
                      v.detected_at = $now
                """,
                obs_key_val=obs_key_val, exp_key_val=exp_key_val, attribute=full_attribute,
                obs_val=str(result.observed_value), exp_val=str(result.expected_value),
                severity=result.severity, comparator=result.comparator, detail=result.detail,
                now=now,
            )
            written += 1
        elif result.status == comp.MATCH:
            del_result = tx.run(
                f"""
                MATCH (obs:{obs_label} {{{obs_key_prop}: $obs_key_val}})
                      -[v:VIOLATES {{violated_attribute: $attribute}}]->(exp:{exp_label} {{{exp_key_prop}: $exp_key_val}})
                WITH v, count(v) AS c
                DELETE v
                RETURN c AS deleted
                """,
                obs_key_val=obs_key_val, exp_key_val=exp_key_val, attribute=full_attribute,
            ).single()
            if del_result and del_result["deleted"]:
                resolved += 1
        # NOT_COMPARABLE: no action — consistent with "never a false verdict".

    return written, resolved


def _analyze_usecase_tx(tx: ManagedTransaction, usecase_name: str) -> tuple[int, int]:
    # fetch_usecase_rows handles SSH Bastion ProxyJump automatically: it
    # uses _FETCH_QUERY_PROXYJUMP (pairing by ssh_context) if Expected nodes
    # with ssh_context exist, otherwise it falls back to the standard
    # _FETCH_QUERY. No change needed here — the correct behavior is inherited.
    rows = fetch_usecase_rows(tx, usecase_name)

    written, resolved = 0, 0

    for row in rows:
        asset_name = row["asset"]
        expected = dict(row["expected"])
        observed = dict(row["observed"])
        observed_key = observed.get("observed_key") or f"{asset_name}::{usecase_name}"

        # Same exclusion as comparison_view.py: the generic profile does
        # not apply to IPsec, for the same structural reason. The
        # comparator registry (TLS or SSH) is chosen from the protocol of
        # the Observed node actually read, not assumed from the use case —
        # see dimensions_for_protocol in comparators.py.
        if observed.get("protocol") != "IPSEC_IKE":
            # exp_key_prop/exp_key_val: the correct Expected node for THIS
            # row has already been resolved by fetch_usecase_rows (via the
            # Asset-[:EXPOSES]-> relationship that, for ProxyJump,
            # distinguishes bastion/ctx1 from appserver/ctx2) — it is
            # "expected" itself. Re-matching it below by use_case alone, as
            # this code used to do, is what caused duplicated findings after
            # expected_per_usecase_unique was removed: since several
            # :Expected nodes can legitimately share the same use_case (the
            # ProxyJump case requires it), that MATCH found three — the
            # generic one plus ctx1 and ctx2 — and MERGE wrote one VIOLATES
            # for each. Using observed_key when present (only on per-context
            # nodes, never on the generic one — see
            # graph_writer._write_bastion_proxyjump_tx) once again pinpoints
            # exactly the right node, a single one.
            expected_key_prop = "observed_key" if expected.get("observed_key") else "use_case"
            expected_key_val = expected.get("observed_key") or usecase_name
            w, r = _apply_dimensions(
                tx, comp.dimensions_for_protocol(observed.get("protocol")), expected, observed,
                obs_label="Observed", obs_key_prop="observed_key", obs_key_val=observed_key,
                exp_label="Expected", exp_key_prop=expected_key_prop, exp_key_val=expected_key_val,
                attribute_prefix="",
            )
            written += w
            resolved += r

        if row["ike_expected"] is not None and row["ike_observed"] is not None:
            ike_exp = dict(row["ike_expected"])
            ike_obs = dict(row["ike_observed"])
            ike_obs_key = ike_obs.get("observed_key") or observed_key
            w, r = _apply_dimensions(
                tx, comp.IKE_SA_DIMENSIONS, ike_exp, ike_obs,
                obs_label="IkeSaObserved", obs_key_prop="observed_key", obs_key_val=ike_obs_key,
                exp_label="IkeSaExpected", exp_key_prop="use_case", exp_key_val=usecase_name,
                attribute_prefix="ike_sa.",
            )
            written += w
            resolved += r

        if row["child_expected"] is not None and row["child_observed"] is not None:
            child_exp = dict(row["child_expected"])
            child_obs = dict(row["child_observed"])
            child_obs_key = child_obs.get("observed_key") or observed_key
            w, r = _apply_dimensions(
                tx, comp.CHILD_SA_DIMENSIONS, child_exp, child_obs,
                obs_label="ChildSaObserved", obs_key_prop="observed_key", obs_key_val=child_obs_key,
                exp_label="ChildSaExpected", exp_key_prop="use_case", exp_key_val=usecase_name,
                attribute_prefix="child_sa.",
            )
            written += w
            resolved += r

    return written, resolved
