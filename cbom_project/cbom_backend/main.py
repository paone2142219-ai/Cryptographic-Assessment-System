# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# main.py — FastAPI server: HTTP/JSON ↔ Bolt boundary
#
# Exposes the REST endpoints the GUI (index.html/app.js) consumes via
# fetch(). This process is the ONLY component holding the Neo4j
# credentials; the browser never talks directly to the database.
#
# Startup:
#   uvicorn main:app --reload --port 8000
#
# Automatically generated interactive documentation (useful to test the
# endpoints without the GUI, during development):
#   http://localhost:8000/docs
# =====================================================================

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from schema import UseCaseInput, WriteResult
from neo4j_client import get_driver, close_driver
from graph_writer import write_usecase, read_usecase_summary
from init_schema import init_schema
from cbom_loader import load_cbom
from drift_engine import run_drift_analysis
from comparison_view import build_comparison_view


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: check the connection and apply the schema constraints.
    get_driver()
    init_schema()
    yield
    # Shutdown: close the connection pool.
    close_driver()


app = FastAPI(
    title="CBOM Manager API",
    description="Translation backend GUI → Neo4j Knowledge Graph",
    version="1.0.0",
    lifespan=lifespan,
)

# The GUI is served as a static file opened in the browser (e.g. via
# `python -m http.server` on a different port, or directly as file:// in
# development): CORS must be open locally. In a real deployment it should
# be restricted to the GUI's exact origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Liveness probe
@app.get("/api/health")
def health_check():
    """Quick check that the backend is reachable and connected to Neo4j."""
    driver = get_driver()
    driver.verify_connectivity()
    return {"status": "ok", "neo4j": "connected"}


@app.post("/api/usecases", response_model=WriteResult)
def create_or_update_usecase(payload: UseCaseInput):
    """
    Main endpoint: receives the complete payload of a use case
    (cryptographic parameters + assets) from the GUI and writes it to the
    graph as UseCase / Policy / Expected / Service / Asset nodes,
    following the relationship schema of the reference Cypher file.

    Idempotent: re-running the same POST with modified values updates the
    existing nodes (MERGE), it does not duplicate them.
    """
    driver = get_driver()
    try:
        result = write_usecase(driver, payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Neo4j write error: {exc}")
    return result


@app.post("/api/ingest/cbom")
def ingest_cbom(cbom: dict):
    """
    Receives the content of cbom.json (the output of pipeline_cbom.py) as
    is — no client-side transformation, the backend does all the
    attribution and extraction work.

    In two distinct phases, deliberately not merged into one:
      1. cbom_loader.load_cbom  — writes the :Observed profiles on the
         assets already declared in the GUI, only for the use cases that
         asset is already associated with (no new attribution invented here).
      2. drift_engine.run_drift_analysis — compares every Observed profile
         just written with the corresponding Expected, and updates the
         VIOLATES relationships accordingly (written if the observed level
         is lower than the expected one, removed if an earlier drift is
         now resolved).

    As idempotent as the two underlying phases: re-running with the same
    cbom.json produces the same final state, it duplicates nothing.
    """
    driver = get_driver()
    try:
        load_result = load_cbom(driver, cbom)
        drift_result = run_drift_analysis(driver)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error during ingest: {exc}")
    return {"status": "ok", "load": load_result, "drift": drift_result}


@app.get("/api/comparison/{usecase_name}")
def get_comparison(usecase_name: str):
    """
    Source of truth for the operator: the complete Parameter /
    Configured / Observed / Status table, for every asset of the use case
    — EVERY evaluated dimension, not only the deviating ones (those alone
    remain the job of /api/findings, which reads VIOLATES).

    Same computation as drift_engine.py (comparators.py, the same
    dimension registries), never a second duplicated comparison logic
    that could drift out of sync with the one writing VIOLATES.
    """
    driver = get_driver()
    try:
        result = build_comparison_view(driver, usecase_name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error computing the comparison: {exc}")
    return result


@app.post("/api/drift/{usecase_name}")
def recompute_drift(usecase_name: str):
    """
    Recomputes VIOLATES for a single use case, without requiring a new
    cbom.json — the Observed profiles are already in the graph since the
    last ingest, only the policy (Expected) changes. Without this
    endpoint, the only way to update VIOLATES after a policy change was
    to reload the whole cbom.json even when the observed data had not
    changed at all: /api/comparison always recomputes live on every
    request (which is why it immediately shows the correct deviation),
    but VIOLATES stayed frozen at the state of the last ingest — not a
    problem of the relationship itself, a gap in the workflow around it.
    """
    driver = get_driver()
    try:
        result = run_drift_analysis(driver, usecase_name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error recomputing the deviation: {exc}")
    return {"status": "ok", "drift": result}


@app.get("/api/usecases/{usecase_name}")
def get_usecase(usecase_name: str):
    """
    Returns the current state of a use case already saved in the graph.
    Used by the GUI to reload the values on tab change, so the dashboard
    always reflects the real Neo4j state and not only the browser's local
    state.
    """
    driver = get_driver()
    result = read_usecase_summary(driver, usecase_name)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Use case '{usecase_name}' not found in the graph")
    return result


@app.get("/api/findings/{usecase_name}")
def get_findings(usecase_name: str):
    """
    Returns the findings (VIOLATES relationships) detected for a use case
    — across all three possible sources: the generic profile
    (CryptoProfile:Expected/Observed, used by TLS/SSH) and, for IPsec use
    cases, the two IKE SA and Child SA sub-profiles
    (IkeSaExpected/IkeSaObserved, ChildSaExpected/ChildSaObserved).

    Three separate queries, not a single one with nested OPTIONAL MATCHes:
    clearer to read, and a syntax bug in one does not stop the other two
    from working. The previous version looked for VIOLATES only towards
    :Expected — after the IKE SA/Child SA sub-profiles were introduced,
    most real findings for IPsec use cases pointed elsewhere, and were
    therefore never found: not a syntax error, an endpoint never updated
    together with the rest.
    """
    driver = get_driver()

    generic_query = """
    MATCH (use:UseCase {name: $usecase_name})<-[:SERVES]-(svc:Service)
    MATCH (a:Asset)-[:HOSTS]->(svc)
    MATCH (a)-[:EXPOSES]->(obs:Observed {use_case: $usecase_name})
          -[v:VIOLATES]->(exp:Expected {use_case: $usecase_name})
    RETURN a.name AS asset, v.violated_attribute AS attribute,
           v.observed_value AS observed, v.expected_value AS expected,
           v.severity AS severity, v.comparator AS comparator,
           v.detail AS detail, v.detected_at AS detected_at
    """
    ike_query = """
    MATCH (use:UseCase {name: $usecase_name})<-[:SERVES]-(svc:Service)
    MATCH (a:Asset)-[:HOSTS]->(svc)
    MATCH (a)-[:EXPOSES]->(:Observed {use_case: $usecase_name})
          -[:HAS_IKE_SA]->(ike_obs:IkeSaObserved)
          -[v:VIOLATES]->(:IkeSaExpected {use_case: $usecase_name})
    RETURN a.name AS asset, v.violated_attribute AS attribute,
           v.observed_value AS observed, v.expected_value AS expected,
           v.severity AS severity, v.comparator AS comparator,
           v.detail AS detail, v.detected_at AS detected_at
    """
    child_query = """
    MATCH (use:UseCase {name: $usecase_name})<-[:SERVES]-(svc:Service)
    MATCH (a:Asset)-[:HOSTS]->(svc)
    MATCH (a)-[:EXPOSES]->(:Observed {use_case: $usecase_name})
          -[:HAS_CHILD_SA]->(child_obs:ChildSaObserved)
          -[v:VIOLATES]->(:ChildSaExpected {use_case: $usecase_name})
    RETURN a.name AS asset, v.violated_attribute AS attribute,
           v.observed_value AS observed, v.expected_value AS expected,
           v.severity AS severity, v.comparator AS comparator,
           v.detail AS detail, v.detected_at AS detected_at
    """

    with driver.session() as session:
        records = (
            session.run(generic_query, usecase_name=usecase_name).data()
            + session.run(ike_query, usecase_name=usecase_name).data()
            + session.run(child_query, usecase_name=usecase_name).data()
        )
    records.sort(key=lambda r: r["severity"] or 0, reverse=True)
    return {"usecase": usecase_name, "findings": records}
