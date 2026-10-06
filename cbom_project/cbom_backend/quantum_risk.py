# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# quantum_risk.py — harvest-now, decrypt-later (HNDL) exposure heuristic
#
# ONE heuristic, applied twice with the same inputs on the use-case side
# and a different posture on the profile side:
#
#   expected exposure = assess(shelf_time_days, expected key-exchange posture)
#                       → "is the POLICY adequate for this data?"
#                       computed by graph_writer when the policy is saved
#   observed exposure = assess(shelf_time_days, worst observed key-exchange
#                       posture over ALL sessions of the use case)
#                       → "is the traffic ACTUALLY exposed?"
#                       computed by cbom_loader at every ingest, and
#                       recomputed by graph_writer when the shelf time changes
#
# The confidentiality lifetime (shelf_time_days) is a declared attribute of
# the USE CASE, i.e. of the data it protects: it is neither an expected nor
# an observed cryptographic property and cannot be inferred from telemetry.
# It therefore lives once, on the UseCase node, and is shared by both
# evaluations — it is never copied onto the Observed profile, which by
# design only holds data observed on the wire (see schema.py).
#
# Why the WORST observed posture, and over every session: HNDL is a passive
# attack on recorded traffic. A single session established with a classical
# key exchange exposes the data it carried, however many other sessions
# used a hybrid one — so the observed posture of a use case is the minimum
# over all its attributed sessions, not the posture of a sample. (The
# :Observed node keeps only the latest session per asset, so this aggregate
# is computed by cbom_loader over the whole cbom.json, not read back from
# the graph.)
#
# Simplification of Mosca's inequality X + Y > Z: only X (shelf time) is
# modeled; Y (migration time) and Z (arrival of a cryptographically
# relevant quantum computer) are not estimated. The heuristic flags the
# most critical combination — data that must stay confidential for at
# least QUANTUM_RISK_SHELF_THRESHOLD_DAYS, protected by classical key
# establishment only. Mirrored for the GUI preview of the expected side by
# computeQuantumRiskPreview() in app.js (same threshold, same rule).
# =====================================================================
from __future__ import annotations

from crypto_levels import POSTURE_CLASSICAL, POSTURE_HYBRID, POSTURE_NATIVE

QUANTUM_RISK_SHELF_THRESHOLD_DAYS = 365

# Same total order as comparators._PQ_POSTURE_RANK — used here to pick the
# worst (lowest) posture among the observed sessions.
POSTURE_RANK = {POSTURE_CLASSICAL: 0, POSTURE_HYBRID: 1, POSTURE_NATIVE: 2}

EXPECTED = "expected"
OBSERVED = "observed"


def worst_posture(postures) -> str | None:
    """Lowest posture in the iterable, None if it is empty (no session)."""
    postures = [p for p in postures if p is not None]
    if not postures:
        return None
    return min(postures, key=lambda p: POSTURE_RANK.get(p, 0))


def assess(shelf_time_days: int | None, posture: str | None, side: str,
           sessions: dict[str, int] | None = None) -> dict:
    """
    Returns {"flag": bool | None, "rationale": str}.

    flag is None — "not evaluable", never a false "no risk" — when the
    posture is unknown: on the observed side this means no session of the
    use case was attributed in the last ingest. It is informational only:
    it never raises and never blocks a write.
    """
    shelf = int(shelf_time_days or 0)
    subject = ("the expected key exchange (policy)" if side == EXPECTED
               else "the worst key exchange observed in real sessions")

    if posture is None:
        return {
            "flag": None,
            "rationale": (
                "No observed session attributed to this use case in the last ingest: "
                "the observed quantum exposure cannot be evaluated."
                if side == OBSERVED else
                "No expected key exchange declared: the expected quantum exposure "
                "cannot be evaluated."
            ),
        }

    breakdown = ""
    if sessions:
        breakdown = (" Observed sessions by key-exchange posture: "
                     + ", ".join(f"{k} {v}" for k, v in sessions.items() if v) + ".")

    long_lived = shelf >= QUANTUM_RISK_SHELF_THRESHOLD_DAYS
    at_risk = long_lived and posture == POSTURE_CLASSICAL

    if at_risk:
        rationale = (
            f"The data must stay confidential for {shelf} days "
            f"(>= {QUANTUM_RISK_SHELF_THRESHOLD_DAYS}) but {subject} is "
            f"'{POSTURE_CLASSICAL}': potential exposure to harvest-now-decrypt-later "
            f"scenarios. Consider migrating to a hybrid or native PQ key exchange."
        )
    elif long_lived:
        rationale = (
            f"High shelf time ({shelf} days) but {subject} is '{posture}': risk "
            f"mitigated compared with the purely classical scenario."
        )
    else:
        rationale = (
            f"Shelf time ({shelf} days) below the alert threshold "
            f"({QUANTUM_RISK_SHELF_THRESHOLD_DAYS} days): quantum risk is not a "
            f"priority for this use case at the moment ({subject}: '{posture}')."
        )
    return {"flag": at_risk, "rationale": rationale + breakdown}
