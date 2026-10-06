# CBOM Enrichment via Ontological Modeling — End-to-end chain

*Sapienza University of Rome*

This guide explains how to instantiate the whole chain, from the network lab to the console showing the declared cryptographic posture against the observed one. There are four distinct systems, connected into a single operational flow.

```
┌─────────────────────────────────────┐
│ Kathará lab                         │
│ (16 containers)                     │
└─────────────────────────────────────┘
                   │
       real traffic (shared/)
                   ▼
┌─────────────────────────────────────┐
│ pipeline_cbom.py                    │
└─────────────────────────────────────┘
                   │
         cbom.json (observed)
                   ▼
┌─────────────────────────────────────┐
│ cbom_backend                        │
│ (FastAPI + Neo4j)                   │
│ comparators.py                      │
│ drift_engine.py                     │
│ comparison_view.py                  │
└─────────────────────────────────────┘
                   │
            ┌──────┴──────────────────────────┐
   VIOLATES (derived)               complete comparison
alerting, aggregate queries     source of truth for the operator
            ▼                                 ▼
┌─────────────────────────────────────┐
│ cbom_manager                        │
│ (GUI - declared policy, Expected;   │
│ Findings tab and Comparison tab)    │
└─────────────────────────────────────┘
```

The principle running through every phase, never violated: **declared data and observed data are never merged into a single judgment before the final explicit comparison**, and that comparison never uses a single universal criterion — every cryptographic parameter has its own comparison semantics (protocol version, tiered robustness, numeric with explicit direction, boolean, set membership), applied atomically, dimension by dimension (`comparators.py`).

---

## Prerequisites

| Tool | Minimum version | Check |
|---|---|---|
| Kathará | any recent version | `kathara --version` |
| Docker | required both for Kathará and for Neo4j | `docker --version` |
| Python | 3.11+ | `python3 --version` |
| Neo4j | 5.x (via Docker, simplest) | — |

No other prerequisite: `cbom_manager` is static HTML/CSS/JS, no bundler, no build.

---

## Phase 1 — The Kathará lab

```bash
cd kathara_crypto_maturity
./build_images.sh          # rebuilds all the images — required after
                            # any change inside images/, not only the
                            # first time
kathara lclean              # cleanup of any previous instance
kathara lstart               # start the 16 containers
```

Generate traffic for at least some of the nine use cases by following the commands in the lab's `README.md`/`TUTORIAL.md`. There is no need to exercise all of them on a first run: the pipeline processes only what it finds.

---

## Phase 2 — Consolidation: from raw traffic to `cbom.json`

```bash
python3 pipeline_cbom/main.py --shared kathara_crypto_maturity/shared/ --output cbom.json
```

Full re-read of `shared/` on every run, no state between one run and the next. For IPsec use cases, `cbom.json` already carries the two distinct cryptographic layers — IKE SA (control channel: `ike_enc`, `ike_prf`, `ike_group`) and Child SA (data channel: `child_sas[].esp_enc`, `esp_group`, `has_pfs`, `declared_pfs_capable`) — never flattened into a single profile, neither here nor in the later phases.

---

## Phase 3 — Backend and graph

### 3.1 Neo4j

```bash
docker run -d --name cbom-neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password_sicura neo4j:5 
```

The password must match the one `cbom_backend/neo4j_client.py` expects by default, or override both with `NEO4J_PASSWORD`.

### 3.2 The FastAPI backend

```bash
cd cbom_backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python3 init_schema.py     # creates constraints and indexes — once,
                            # or every time schema.py changes

uvicorn main:app --reload --port 8000
```

Check: `curl http://localhost:8000/docs` must show the Swagger page — from there you can also try the endpoints manually, without writing `curl` by hand (especially useful for `/api/ingest/cbom`, which requires pasting a whole JSON).

---

## Phase 4 — Declaring the policy: the GUI

```bash
cd cbom_manager
python3 -m http.server 8080
```

Open `http://localhost:8080`. For each of the nine use cases: review the cryptographic parameters, correct them if your real policy differs, set the governance parameters, then **"Save policy"**.

For the two IPsec use cases (VPN Road Warrior, Site-to-Site VPN), the GUI declares **two distinct sub-profiles**, not one: the control-channel one (IKE version, phase 1 encryption/PRF/DH group, authentication method, rekey time) and the data-channel one (ESP encryption, DH group for PFS, Child SA lifetime) — consistent with the two-layer structure the protocol itself imposes, and with what `cbom.json` already carries from Phase 2.

**This step is not optional, even for a single use case you want analyzed**: without a saved `Expected` node, and without the `Asset`s declared with the same hostname used in `asset_inventory.json`, the later phases have nothing to compare the observed data with.

> **Vocabulary alignment (GUI ↔ backend).** Some values selected in the GUI are validated by enums in `cbom_backend/schema.py` and must match byte-for-byte: data sensitivity (`public` / `internal` / `confidential` / `critical`) and the derived PQC posture (`classical` / `hybrid (classical+PQ)` / `native PQ`). A mismatch between `data.js`/`app.js` and `schema.py` shows up as **HTTP 422** on "Save policy". If you rename one of these values, change it in every mirror listed in the header of `schema.py`.

---

## Phase 5 — The comparison: from `cbom.json` to two distinct views

```bash
curl -X POST http://localhost:8000/api/ingest/cbom \
     -H "Content-Type: application/json" \
     --data @cbom.json
```

Expected response:

```json
{
  "status": "ok",
  "load": {"observed_written": 42, "skipped_no_profile": 0, "skipped_no_asset_hint": 1, "skipped_asset_without_usecase": 5,
           "observed_kex_summary": {"API Gateway TLS": {"sessions": 60, "worst": "classical", "classical": 12, "hybrid (classical+PQ)": 48, "native PQ": 0}, "...": {}}},
  "drift": {"usecases_analyzed": 9, "violations_written": 4, "violations_resolved": 0}
}
```

A high `skipped_asset_without_usecase` is almost always the symptom of Phase 4 not completed for some asset — not a pipeline error.

From here, two distinct views on the same computation, never duplicated:

- **`GET /api/findings/{use_case}`** ("Detected findings" tab in the GUI) — only the deviations, with severity and comparator provenance. Designed for alerting: "what is wrong, right now".
- **`GET /api/comparison/{use_case}`** ("Expected/Observed comparison" tab, new) — **every** evaluated parameter, not only the deviations: match, deviation, and honestly also `not_comparable` when the data is missing on one side. It is the source of truth designed for a complete human reading of the posture, not only of its problems.

---

## The repeating cycle

```bash
# generate more traffic in the lab...
python3 pipeline_cbom/main.py --shared shared/ --output cbom.json
curl -X POST http://localhost:8000/api/ingest/cbom --data @cbom.json
# reload findings and/or comparison in the GUI
```




---

## How the comparison works, in short

Not a single universal criterion — six typed comparators (`comparators.py`), each with explicit semantics, chosen per dimension:

| Comparator | Used for | Semantics |
|---|---|---|
| `ordinal_enum` | Protocol version (TLS, IKE, SSH) | Explicit total order — TLS 1.2 < 1.3, never ambiguous |
| `tiered_classification` | KEX, encryption, MAC, host key | Robustness tiers (SAFE/MARGINAL/VULNERABLE/BROKEN), not a false linear ranking |
| `numeric_max_better` | Key length | Higher is better |
| `numeric_min_better` | Rekey time, lifetime | Lower is better — the opposite direction to key length, never confused |
| `boolean_implication` | PFS, declared PFS capability | Violation only if required and not observed — never the other way round |
| `set_membership` | Authentication method | No order: membership in a set of values allowed by the policy |

A parameter with data missing on one side never produces a verdict — it stays explicitly `not_comparable`, both in the findings and in the complete comparison.

## Quantum (harvest-now, decrypt-later) exposure — evaluated on both sides

The PQC posture (`classical` / `hybrid (classical+PQ)` / `native PQ`) is a property of the **key exchange only** — the TLS curve/group, the SSH KEX algorithm, the IKE key exchange (IKE_SA_INIT group plus any RFC 9370 additional key exchanges, written `ECP_384+ML_KEM_768`). Signatures, ciphers and MACs do not change it: only key establishment decides whether traffic recorded today can be decrypted later. It is derived by **one function** (`crypto_levels.kex_pq_posture`) applied to the **same field** (`kex`) of the Expected and of the Observed profile; the GUI (`kexPQPosture` in `app.js`) only shows a live preview, the backend recomputes the expected posture itself on save.

The confidentiality lifetime of the data (`shelf_time_days`) is declared by the operator and cannot be inferred from telemetry. It is an attribute of the **use case**, not of either profile, so it is stored once on `UseCase` and combined with the same heuristic (`quantum_risk.py`, a simplification of Mosca's inequality that models only X) on both sides:

| UseCase property | Inputs | Computed |
|---|---|---|
| `quantum_risk_expected_flag` | shelf time × expected key-exchange posture | on "Save policy" |
| `quantum_risk_observed_flag` | shelf time × **worst** key-exchange posture over **every** observed session of the use case | on every ingest, and again on "Save policy" (the shelf time may have changed) |

The observed side takes the worst session, not a sample, because one session established classically is enough to expose the data it carried. The per-posture session counts are stored on the `UseCase` (`observed_kex_sessions_*`, `observed_kex_posture_worst`) and returned by the ingest as `load.observed_kex_summary`. A use case with no attributed session in the last ingest gets `quantum_risk_observed_flag = null` ("not evaluable"), never a false "no risk". Both flags are shown side by side in the "Expected/Observed comparison" tab.

## Known, declared limitations

The comparison does not yet cover `mutual_auth` for the generic profile (derived in the GUI but not yet present in `Observed` for TLS/SSH), nor any notion of "preferred curve family" beyond the robustness tier. None of these is a hidden limitation: they are explicitly commented in the code of the dimension registries (`comparators.py`), the natural starting point if you want to extend the coverage.
