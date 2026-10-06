# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# init_schema.py — Execution of the structural constraints
#
# Runs ONCE (it is idempotent thanks to IF NOT EXISTS) the constraints
# and indexes defined in section 2 of the reference Cypher file. They
# must run before any application write: they are the part of the schema
# actually enforced by the Neo4j engine.
#
# Usage:
#   python init_schema.py
#
# UPDATE — Lifecycle & Data Governance: added two secondary indexes (not
# present in the original section 2 of the reference Cypher file) to
# support the new properties introduced to enrich the Expected profile
# and the UseCase node.
# =====================================================================

from neo4j_client import get_driver, close_driver

# Exact replica of the "2. UNIQUENESS CONSTRAINTS" section of the
# reference Cypher file provided. Kept here as a list of independent
# statements because CREATE CONSTRAINT / CREATE INDEX commands cannot be
# combined into a single multi-statement call via the Python driver.
SCHEMA_STATEMENTS = [
    """
    CREATE CONSTRAINT asset_name_unique IF NOT EXISTS
    FOR (a:Asset) REQUIRE a.name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT usecase_name_unique IF NOT EXISTS
    FOR (u:UseCase) REQUIRE u.name IS UNIQUE
    """,
    """
    CREATE CONSTRAINT policy_usecase_unique IF NOT EXISTS
    FOR (p:Policy) REQUIRE p.use_case IS UNIQUE
    """,
    # expected_per_usecase_unique — REMOVED. The original constraint ("a
    # single :Expected node per use_case in the whole graph") contradicts
    # the design of the SSH Bastion ProxyJump case:
    # graph_writer._write_bastion_proxyjump_tx DELIBERATELY writes two
    # :Expected nodes sharing the same use_case (one for bastion/ctx1, one
    # for appserver/ctx2 — this is how
    # comparison_view._FETCH_QUERY_PROXYJUMP retrieves both, filtering on
    # ssh_context). With this constraint active, writing the second node
    # always failed with ConstraintValidationFailed — not only on
    # re-ingests, already on the very first save of a ProxyJump use case.
    # Idempotency for ANY use case is still guaranteed by MERGE on the
    # correct logical key: use_case for "simple" Expected nodes
    # (_write_usecase_tx), observed_key for per-context ones
    # (_write_bastion_proxyjump_tx) — see expected_proxyjump_key_unique
    # below, which stays and keeps preventing REAL duplicates (the same
    # hop written twice).
    #
    # If this schema was already initialized earlier, the constraint stays
    # in the database even after removing this entry (IF NOT EXISTS only
    # prevents re-creation, it does not remove the existing one): drop it
    # once with:
    #   DROP CONSTRAINT expected_per_usecase_unique IF EXISTS
    """
    CREATE CONSTRAINT expected_proxyjump_key_unique IF NOT EXISTS
    FOR (e:Expected) REQUIRE e.observed_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT service_key_unique IF NOT EXISTS
    FOR (s:Service) REQUIRE s.service_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT observed_key_unique IF NOT EXISTS
    FOR (o:Observed) REQUIRE o.observed_key IS UNIQUE
    """,
    """
    CREATE INDEX asset_criticality_idx IF NOT EXISTS
    FOR (a:Asset) ON (a.criticality)
    """,
    """
    CREATE INDEX violates_severity_idx IF NOT EXISTS
    FOR ()-[v:VIOLATES]-() ON (v.severity)
    """,
    # ── Lifecycle & Data Governance ─────────────────────────────────
    # They support triage queries: "which use cases are at quantum risk"
    # and "which expected profiles protect critical/confidential data",
    # both intended for follow-up dashboards on the CBOM enrichment.
    # quantum_risk_flag was split into an expected/observed pair (see
    # quantum_risk.py). An old usecase_quantum_risk_idx on the former
    # property is harmless but useless; drop it once with:
    #   DROP INDEX usecase_quantum_risk_idx IF EXISTS
    """
    CREATE INDEX usecase_quantum_risk_expected_idx IF NOT EXISTS
    FOR (u:UseCase) ON (u.quantum_risk_expected_flag)
    """,
    """
    CREATE INDEX usecase_quantum_risk_observed_idx IF NOT EXISTS
    FOR (u:UseCase) ON (u.quantum_risk_observed_flag)
    """,
    """
    CREATE INDEX expected_data_sensitivity_idx IF NOT EXISTS
    FOR (e:Expected) ON (e.data_sensitivity)
    """,
    # ── IKE SA / Child SA — IPsec sub-profiles, dedicated labels ───────
    # They do not reuse :Expected/:Observed: those labels already have a
    # uniqueness constraint on use_case scoped to CryptoProfile — a second
    # node type with the same label and the same use_case would violate
    # that constraint, not extend it.
    """
    CREATE CONSTRAINT ikesa_expected_usecase_unique IF NOT EXISTS
    FOR (i:IkeSaExpected) REQUIRE i.use_case IS UNIQUE
    """,
    """
    CREATE CONSTRAINT ikesa_observed_key_unique IF NOT EXISTS
    FOR (i:IkeSaObserved) REQUIRE i.observed_key IS UNIQUE
    """,
    """
    CREATE CONSTRAINT childsa_expected_usecase_unique IF NOT EXISTS
    FOR (c:ChildSaExpected) REQUIRE c.use_case IS UNIQUE
    """,
    """
    CREATE CONSTRAINT childsa_observed_key_unique IF NOT EXISTS
    FOR (c:ChildSaObserved) REQUIRE c.observed_key IS UNIQUE
    """,
]


def init_schema() -> None:
    driver = get_driver()
    with driver.session() as session:
        for statement in SCHEMA_STATEMENTS:
            session.run(statement)
            print(f"  ✓ {statement.strip().splitlines()[0].strip()}")
    print(f"\nSchema initialized: {len(SCHEMA_STATEMENTS)} constraints/indexes applied.")


if __name__ == "__main__":
    print("Initializing Neo4j schema (constraints + indexes)...\n")
    init_schema()
    close_driver()
