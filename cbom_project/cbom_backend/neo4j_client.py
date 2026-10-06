# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# neo4j_client.py — Bolt connection management
#
# Centralizes the creation of the Neo4j driver. The driver is thread-safe
# and keeps an internal connection pool: it must be instantiated ONCE for
# the whole application lifecycle (not per request).
# =====================================================================

import os
from neo4j import Driver, GraphDatabase

# Default values for a local Neo4j instance (Docker or Desktop).
# In production these should be read from environment variables or from
# a .env file — here they are exposed as explicit defaults for ease of
# use in the lab.
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
# NOTE: the default value below is the actual password of the local lab
# instance — it is a credential, not a label, so it is deliberately left
# unchanged by the English translation. Override it with NEO4J_PASSWORD.
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password_sicura")

_driver: Driver | None = None


def get_driver() -> Driver:
    """
    Returns the shared Neo4j driver, creating it on first use (singleton
    pattern). Connectivity is checked only at creation time, not on every
    call, to avoid adding needless latency.
    """
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
        )
        _driver.verify_connectivity()
    return _driver


def close_driver() -> None:
    """To be called at application shutdown (see main.py)."""
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
