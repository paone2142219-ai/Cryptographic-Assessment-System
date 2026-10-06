# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# comparators.py — typed Expected/Observed comparison, per family
#
# Origin of this module: an explicit, parameter-by-parameter analysis of
# which cryptographic properties actually admit an ordering relation and
# which do not (see project discussion). The conclusion: most parameters
# DO have a rigorous comparison criterion — but not the SAME one for all.
# Forcing every dimension through a single comparator (as the first
# version of drift_engine.py did, with only the 4-level classification)
# conflated dimensions with different semantics: a protocol version is a
# total order, a DH group is a tiered order, a rekey time is numeric with
# a "lower is better" direction (the opposite of key length), an
# authentication method has no order at all.
#
# Every comparator returns an explicit ComparisonResult, with three
# possible states — never just "compliant/violated":
#   - MATCH:          the observed level equals or exceeds the expected one
#   - DEVIATION:      the observed level is lower than the expected one
#   - NOT_COMPARABLE: data missing on at least one side, or the value is
#                     not recognized — never a false "compliant", never a
#                     false "violated".
#
# This module is the source of truth both for VIOLATES (the derived
# artifact, for alerting/aggregate queries) and for the complete
# comparison view (the source of truth for the operator, see
# comparison_view.py) — one computation, two representations, never two
# duplicated logics that could drift out of sync.
# =====================================================================
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

import crypto_levels as cl

MATCH = "match"
DEVIATION = "deviation"
NOT_COMPARABLE = "not_comparable"

# Readable name of the evaluation criterion/matrix, shown in the GUI next
# to every comparison row — the operator must be able to see WHICH
# criterion was applied, not only its outcome.
CRITERION_LABELS = {
    "ordinal_enum": "Explicit total order (protocol version)",
    "tiered_classification": "Tiered classification (SAFE / MARGINAL / VULNERABLE / BROKEN)",
    "numeric_max_better": "Numeric comparison — higher value is more secure",
    "numeric_min_better": "Numeric comparison — lower value is more secure",
    "boolean_implication": "Logical implication (required ⇒ observed)",
    "set_membership": "Membership in the set of values allowed by the policy",
}


@dataclass
class ComparisonResult:
    status: str                    # MATCH | DEVIATION | NOT_COMPARABLE
    expected_value: Any = None
    observed_value: Any = None
    severity: float = 0.0          # meaningful only if status == DEVIATION, 0-1 scale
    comparator: str = ""           # name of the comparator used — traceability, never implicit
    detail: str = ""               # readable explanation, shown in the comparison view
    # True: same value, literally. False: MATCH reached through tier
    # equivalence, but the observed algorithm is not the declared one
    # (e.g. expected "hmac-sha2-512-etm", observed
    # "hmac-sha2-256-etm@openssh.com" — both SAFE, but not the same
    # algorithm). None when the distinction does not apply (numeric or
    # boolean comparators, or a status other than MATCH). Without this
    # field, "Compliant" hid an algorithm substitution behind an
    # equivalent robustness tier — real information lost, not a
    # computation error.
    exact_match: bool | None = None
    # The explicit symbolic relation used for the verdict — not the
    # narrative sentence (that is 'detail'), the notation itself: "SAFE ≥
    # MARGINAL", "4096 ≥ 2048", "TLSv13 (rank 3) ≥ TLS 1.3 (rank 3)".
    # Shown in the GUI next to the criterion, so the operator sees the
    # inequality applied, not only its narrated consequence.
    inequality: str = ""
    # Readable name of the evaluation matrix/criterion used — distinct
    # from 'comparator' (the technical identifier, e.g.
    # "tiered_classification"): this is the text shown in the GUI.
    criterion_label: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "expected_value": self.expected_value,
            "observed_value": self.observed_value,
            "severity": self.severity,
            "comparator": self.comparator,
            "detail": self.detail,
            "exact_match": self.exact_match,
            "inequality": self.inequality,
            "criterion_label": self.criterion_label,
        }


def _not_comparable(exp, obs, comparator: str, reason: str) -> ComparisonResult:
    r = ComparisonResult(NOT_COMPARABLE, exp, obs, 0.0, comparator, reason)
    r.inequality = "—"
    r.criterion_label = CRITERION_LABELS.get(comparator, comparator)
    return r


def _missing_side_reason(exp, obs) -> str:
    """Explicit message about WHICH side is missing — 'data absent' alone
    does not tell the operator whether the problem is a policy never
    declared in the GUI or an observation never received from the
    pipeline: two entirely different corrective actions."""
    if exp is None and obs is None:
        return "No value either declared in the policy or observed — the parameter was not configured in the GUI and does not appear in the observed traffic."
    if exp is None:
        return "No value declared in the policy for this parameter — it must be set in the GUI before the comparison is possible."
    return "No value observed for this parameter in this sample — the pipeline has not captured it yet, or the corresponding traffic has not occurred yet."


def _non_numeric_reason(exp_val, obs_val) -> str:
    """Distinct from _missing_side_reason: here it distinguishes 'absent'
    (None, never declared/observed) from 'present but not numeric' (a
    value exists, but contains no extractable digits) — two situations
    requiring different interventions, which the operator must be able
    to recognize separately."""
    def _describe(val, side):
        if val is None:
            return f"no {side} value"
        return f"{side} {val!r}, but it contains no recognizable number"

    exp_bad = _extract_number(exp_val) is None
    obs_bad = _extract_number(obs_val) is None
    if exp_bad and obs_bad:
        return f"Policy: {_describe(exp_val, 'declared')}. Observation: {_describe(obs_val, 'observed')}."
    if exp_bad:
        return f"Policy: {_describe(exp_val, 'declared')} — check the parameter in the GUI."
    return f"Observation: {_describe(obs_val, 'observed')} — check how the pipeline extracts the data."


# ─── 1. ORDINAL ENUM — explicit total order (protocol versions) ──────────
# E.g. TLS 1.0 < 1.1 < 1.2 < 1.3. The rank table is the only place where
# domain knowledge must be declared; the comparator itself is generic and
# reusable for any ordered enumeration.

def cmp_ordinal_enum(exp_val: str | None, obs_val: str | None,
                      rank_lookup: Callable[[str], int | None]) -> ComparisonResult:
    if exp_val is None or obs_val is None:
        return _not_comparable(exp_val, obs_val, "ordinal_enum", _missing_side_reason(exp_val, obs_val))

    exp_rank = rank_lookup(exp_val)
    obs_rank = rank_lookup(obs_val)
    if exp_rank is None or obs_rank is None:
        return _not_comparable(
            exp_val, obs_val, "ordinal_enum",
            f"value not recognized in the rank table (expected={exp_val!r}, observed={obs_val!r})",
        )

    if obs_rank >= exp_rank:
        if obs_rank == exp_rank:
            detail = f"The observed version ({obs_val}) matches the one required by the policy."
        else:
            detail = (f"The observed version ({obs_val}) is newer than the required one "
                      f"({exp_val}) — no security feature of the required version is lost.")
        r = ComparisonResult(MATCH, exp_val, obs_val, 0.0, "ordinal_enum", detail)
        r.inequality = f"rank({obs_val})={obs_rank} ≥ rank({exp_val})={exp_rank}"
        r.criterion_label = CRITERION_LABELS["ordinal_enum"]
        return r
    # Severity proportional to the rank distance, not binary: a version
    # one step behind weighs less than two.
    severity = round(min(1.0, (exp_rank - obs_rank) / 3), 2)
    detail = (f"The observed version ({obs_val}) is older than the one required by the policy "
              f"({exp_val}) — it exposes known weaknesses of the superseded version, "
              f"which the policy intended to exclude.")
    r = ComparisonResult(DEVIATION, exp_val, obs_val, severity, "ordinal_enum", detail)
    r.inequality = f"rank({obs_val})={obs_rank} < rank({exp_val})={exp_rank}"
    r.criterion_label = CRITERION_LABELS["ordinal_enum"]
    return r


def _tls_version_rank(v: str) -> int | None:
    """Tolerant of both real vocabularies: 'TLSv13' (Zeek) and
    'TLS 1.3 only' (GUI menu) — normalizes before looking up, the same
    principle already applied in crypto_levels.py."""
    t = v.lower()
    if "1.3" in t or "v13" in t: return 3
    if "1.2" in t or "v12" in t: return 2
    if "1.1" in t or "v11" in t: return 1
    if "1.0" in t or "v10" in t: return 0
    return None


def _ike_version_rank(v: str) -> int | None:
    t = v.lower()
    if "ikev2" in t or "v2" in t: return 1
    if "ikev1" in t or "v1" in t: return 0
    return None


def _ssh_version_rank(v: str) -> int | None:
    t = v.lower()
    if "v2" in t or t.strip() == "2": return 1
    if "v1" in t or t.strip() == "1": return 0
    return None


PROTOCOL_VERSION_RANKERS = {
    "TLS": _tls_version_rank,
    "IPSEC_IKE": _ike_version_rank,
    "SSH": _ssh_version_rank,
}


# ─── 2. TIERED CLASSIFICATION — robustness tiers, not a total order ──────
# For KEX/CIPHER/MAC/HOSTKEY: X25519 and P-384 are both "SAFE" with no
# universally accepted "X25519 > P-384" — a total order would be false
# rigor. The tiers (SAFE/MARGINAL/VULNERABLE/BROKEN) are the level of
# granularity the domain actually admits, not a simplification: it reuses
# the same tables as crypto_levels.py, never duplicated here.

def cmp_tiered_classification(exp_val: str | None, obs_val: str | None,
                                classify: Callable[[str], str]) -> ComparisonResult:
    if exp_val is None or obs_val is None:
        return _not_comparable(exp_val, obs_val, "tiered_classification", _missing_side_reason(exp_val, obs_val))

    exp_level = classify(exp_val)
    obs_level = classify(obs_val)
    # A value the classifier does not recognize (UNKNOWN) is not a
    # "middle level" — it is an absence of information. Treating it as
    # 0.5, as this function did before, produced a false MATCH every time
    # the recognized side was MARGINAL or above: a real bug, found by
    # comparing a policy concept ("Verified certificate (internal CA)")
    # against a real algorithm name ("ecdsa-256") — neither was the
    # problem, the defect was treating UNKNOWN as data, not as an absence.
    if exp_level == cl.UNKNOWN or obs_level == cl.UNKNOWN:
        unknown_side = "expected" if exp_level == cl.UNKNOWN else "observed"
        reason = (f"The {unknown_side} value ({exp_val if unknown_side == 'expected' else obs_val}) "
                  f"is not an algorithm name recognized by the classifier — its robustness tier "
                  f"cannot be established, so it cannot be compared.")
        return _not_comparable(exp_val, obs_val, "tiered_classification", reason)
    exp_score = cl.LEVEL_SCORE.get(exp_level, 0.5)
    obs_score = cl.LEVEL_SCORE.get(obs_level, 0.5)
    # Raw, not semantic, comparison: it only says whether the two strings
    # are literally the same thing (modulo case and separators) — it does
    # not prove they are the "same algorithm" in a rigorous cryptographic
    # sense (two different names for the same primitive would still yield
    # exact_match=False). Sufficient for the purpose: distinguishing
    # "nothing was touched" from "it was replaced with something
    # equivalent but different".
    exact = _normalize_for_exact_compare(exp_val) == _normalize_for_exact_compare(obs_val)

    if obs_score >= exp_score:
        if exact:
            detail = f"The observed algorithm ({obs_val}) is exactly the one declared in the policy, classified {obs_level}."
        else:
            detail = (f"The observed algorithm ({obs_val}, {obs_level}) differs from the one declared in the policy "
                      f"({exp_val}, {exp_level}), but belongs to the same robustness tier or a higher one — "
                      f"it is a substitution, not a weakening: no cryptographic guarantee of the policy is lost.")
        r = ComparisonResult(MATCH, exp_val, obs_val, 0.0, "tiered_classification", detail)
        r.exact_match = exact
        r.inequality = f"{obs_level}({obs_score:.2f}) ≥ {exp_level}({exp_score:.2f})"
        r.criterion_label = CRITERION_LABELS["tiered_classification"]
        return r
    severity = round(exp_score - obs_score, 2)
    detail = (f"The observed algorithm ({obs_val}) is classified {obs_level}, a robustness tier "
              f"lower than the one required by the policy through {exp_val} ({exp_level}).")
    r = ComparisonResult(DEVIATION, exp_val, obs_val, severity, "tiered_classification", detail)
    r.exact_match = exact
    r.inequality = f"{obs_level}({obs_score:.2f}) < {exp_level}({exp_score:.2f})"
    r.criterion_label = CRITERION_LABELS["tiered_classification"]
    return r


def _normalize_for_exact_compare(v: str) -> str:
    return v.lower().replace("-", "").replace("_", "").split("@")[0]


# ─── 3/4. NUMERIC — explicit direction, never assumed ────────────────────
# Two variants because the "good" direction changes with the parameter: a
# higher key length is more secure, and so is a lower rekey time (more
# frequent rotation = smaller exposure window). Confusing them would be a
# sign error, not just an elegance issue — a rekey_time compared with
# "higher is better" would reward exactly the worst configuration.

_NUM_RE = re.compile(r"(\d+(?:\.\d+)?)")


def _extract_number(val) -> float | None:
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    m = _NUM_RE.search(str(val))
    return float(m.group(1)) if m else None


def cmp_numeric_max_better(exp_val, obs_val, max_deviation_ref: float = 1024) -> ComparisonResult:
    """E.g. key length: 4096 > 2048. max_deviation_ref normalizes the
    severity (a 1024-bit difference is already maximum severity)."""
    exp_n, obs_n = _extract_number(exp_val), _extract_number(obs_val)
    if exp_n is None or obs_n is None:
        return _not_comparable(exp_val, obs_val, "numeric_max_better", _non_numeric_reason(exp_val, obs_val))
    if obs_n >= exp_n:
        detail = (f"The observed value ({obs_n:g}) is equal to or above the minimum required by the policy "
                  f"({exp_n:g}) — here a higher value means a larger security margin, not a smaller one.")
        r = ComparisonResult(MATCH, exp_val, obs_val, 0.0, "numeric_max_better", detail)
        r.inequality = f"{obs_n:g} ≥ {exp_n:g}"
        r.criterion_label = CRITERION_LABELS["numeric_max_better"]
        return r
    severity = round(min(1.0, (exp_n - obs_n) / max_deviation_ref), 2)
    detail = (f"The observed value ({obs_n:g}) is below the minimum required by the policy ({exp_n:g}) "
              f"— here a lower value reduces the expected security margin.")
    r = ComparisonResult(DEVIATION, exp_val, obs_val, severity, "numeric_max_better", detail)
    r.inequality = f"{obs_n:g} < {exp_n:g}"
    r.criterion_label = CRITERION_LABELS["numeric_max_better"]
    return r


def cmp_numeric_min_better(exp_val, obs_val, max_deviation_ref: float = 86400) -> ComparisonResult:
    """E.g. rekey time: 24h (86400s) is more secure than 72h. Violation if
    the observed value is HIGHER than the expected one (less frequent
    rotation than declared). Default max_deviation_ref: a whole day of
    difference is already maximum severity."""
    exp_n, obs_n = _extract_number(exp_val), _extract_number(obs_val)
    if exp_n is None or obs_n is None:
        return _not_comparable(exp_val, obs_val, "numeric_min_better", _non_numeric_reason(exp_val, obs_val))
    if obs_n <= exp_n:
        detail = (f"The observed value ({obs_n:g}) is equal to or below the maximum allowed by the policy "
                  f"({exp_n:g}) — here a lower value means a key rotation as frequent as or more frequent "
                  f"than required, hence an equal or larger security margin.")
        r = ComparisonResult(MATCH, exp_val, obs_val, 0.0, "numeric_min_better", detail)
        r.inequality = f"{obs_n:g} ≤ {exp_n:g}"
        r.criterion_label = CRITERION_LABELS["numeric_min_better"]
        return r
    severity = round(min(1.0, (obs_n - exp_n) / max_deviation_ref), 2)
    detail = (f"The observed value ({obs_n:g}) exceeds the maximum allowed by the policy ({exp_n:g}) "
              f"— the key stays in use longer than the policy permits, widening the exposure window "
              f"in case of compromise.")
    r = ComparisonResult(DEVIATION, exp_val, obs_val, severity, "numeric_min_better", detail)
    r.inequality = f"{obs_n:g} > {exp_n:g}"
    r.criterion_label = CRITERION_LABELS["numeric_min_better"]
    return r


# ─── 5. BOOLEAN IMPLICATION — not an order, a logical implication ────────
# PFS, mutual auth: the violation exists in one direction only. If the
# policy requires PFS (expected=True) and it is not observed, it is a
# deviation. If the policy does NOT require it (expected=False) but it is
# observed anyway, it is not a deviation — it is an extra margin, never
# penalized.

def cmp_boolean_implication(exp_val: bool | None, obs_val: bool | None) -> ComparisonResult:
    if exp_val is None or obs_val is None:
        return _not_comparable(exp_val, obs_val, "boolean_implication", _missing_side_reason(exp_val, obs_val))
    if exp_val is False:
        # Not required by the policy: any observed value is fine.
        detail = ("The policy does not require this property — any observed value is acceptable, "
                  "its presence as an extra is never penalized.")
        r = ComparisonResult(MATCH, exp_val, obs_val, 0.0, "boolean_implication", detail)
        r.inequality = f"required=False ⇒ observed={obs_val} always accepted"
        r.criterion_label = CRITERION_LABELS["boolean_implication"]
        return r
    if obs_val is True:
        detail = "The policy requires this property, and it was observed as present."
        r = ComparisonResult(MATCH, exp_val, obs_val, 0.0, "boolean_implication", detail)
        r.inequality = "required=True ⇒ observed=True"
        r.criterion_label = CRITERION_LABELS["boolean_implication"]
        return r
    detail = ("The policy requires this property, but it was not observed in this sample "
              "— it may reflect the real state of the system, or a limitation of the sampling "
              "moment: check the specific context before treating it as a configuration defect.")
    r = ComparisonResult(DEVIATION, exp_val, obs_val, 1.0, "boolean_implication", detail)
    r.inequality = "required=True ⇒ observed=False (violated)"
    r.criterion_label = CRITERION_LABELS["boolean_implication"]
    return r


# ─── 6. SET MEMBERSHIP — no order, only membership ───────────────────────
# auth_method: PSK is not "less" than a certificate in any orderable sense
# — it is a categorical policy choice. The only legitimate comparison is
# "is the observed value among those allowed by the policy?", never a
# computed robustness level.

def cmp_set_membership(exp_val: str | None, obs_val: str | None) -> ComparisonResult:
    if exp_val is None or obs_val is None:
        return _not_comparable(exp_val, obs_val, "set_membership", _missing_side_reason(exp_val, obs_val))
    # The expected value itself is the allowed value(s) — if the GUI ever
    # allows declaring more than one (a list), it is enough to extend
    # exp_val to an iterable here: the function does not change structure.
    allowed = exp_val if isinstance(exp_val, (list, set, tuple)) else {exp_val}
    allowed_list = ", ".join(str(a) for a in allowed)
    if obs_val in allowed:
        detail = (f"The observed method ({obs_val}) is among those allowed by the policy — there is no "
                  f"robustness scale among the allowed methods here, it is a categorical choice: "
                  f"belonging to the allowed set is the only criterion, not a gradation.")
        r = ComparisonResult(MATCH, exp_val, obs_val, 0.0, "set_membership", detail)
        r.inequality = f"{obs_val!r} ∈ {{{allowed_list}}}"
        r.criterion_label = CRITERION_LABELS["set_membership"]
        return r
    detail = (f"The observed method ({obs_val}) is not among those allowed by the policy ({allowed_list}) "
              f"— a configuration choice different from the declared one, not gradable by robustness: "
              f"either it is the required one, or it is not.")
    r = ComparisonResult(DEVIATION, exp_val, obs_val, 1.0, "set_membership", detail)
    r.inequality = f"{obs_val!r} ∉ {{{allowed_list}}}"
    r.criterion_label = CRITERION_LABELS["set_membership"]
    return r


# =====================================================================
# DIMENSION REGISTRIES — one registry per profile type, each dimension an
# atomic, isolated function (expected_dict, observed_dict) ->
# ComparisonResult. No dimension shares state with another: evaluating
# them is deliberately independent, dimension by dimension — a bug in the
# 'cipher' comparator can never contaminate the 'kex' one, because there
# is no shared code path beyond reading the two input dictionaries.
# =====================================================================

# ─── Generic profile (TLS, SSH, and every other non-IPsec use case) ──────

def _compare_protocol_version(exp: dict, obs: dict) -> ComparisonResult:
    protocol = obs.get("protocol") or exp.get("protocol")
    ranker = PROTOCOL_VERSION_RANKERS.get(protocol)
    exp_val, obs_val = exp.get("protocol_version"), obs.get("protocol_version")
    if ranker is None:
        return _not_comparable(exp_val, obs_val, "ordinal_enum",
                                f"no version ranker registered for protocol {protocol!r}")
    return cmp_ordinal_enum(exp_val, obs_val, ranker)


def _compare_kex(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_tiered_classification(exp.get("kex"), obs.get("kex"), cl.kex_level)


def _compare_cipher(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_tiered_classification(exp.get("cipher"), obs.get("cipher"), cl.cipher_level)


# In modern TLS (1.2 with AEAD cipher suites, mandatory in 1.3) the MAC is
# not a parameter negotiated independently of the cipher suite — it is a
# deterministic consequence of it: choosing TLS_AES_256_GCM_SHA384 implies
# SHA-384 as the associated function, there is no combination in which
# encryption and MAC are chosen separately. An independent `mac` field to
# declare in Expected for this protocol is therefore a degree of freedom
# the protocol does not offer — hence the empty entries observed for TLS
# use cases (e.g. API Gateway): neither missing capture data nor an
# operator oversight, but a field with nothing independent to declare.
# cbom_loader.py already reflects this on the Observed side
# (mac=rec.get("cipher") for TLS, with the same comment); here the same
# principle is applied on the Expected side too, so that the comparison
# happens on the only real source of truth — the cipher suite — on both
# sides, instead of between an artificially populated field and a
# structurally empty one.
#
# For SSH and for the IKE SA (see IKE_SA_DIMENSIONS below) the MAC/PRF
# instead remains a separately negotiated parameter (e.g.
# hmac-sha2-256-etm@openssh.com, HMAC_SHA2_384): there the independent
# `mac` field still makes sense and is compared as such, unchanged.
def _compare_mac(exp: dict, obs: dict) -> ComparisonResult:
    protocol = obs.get("protocol") or exp.get("protocol")
    if protocol == "TLS":
        return cmp_tiered_classification(
            exp.get("cipher"), obs.get("cipher"), lambda v: cl.mac_level(v, None)
        )
    return cmp_tiered_classification(exp.get("mac"), obs.get("mac"), lambda v: cl.mac_level(None, v))


# Translation of the real reasons the certificate is not observable,
# already present in cbom.json as cert_observation_method (produced by
# pipeline_cbom/parsers/tls_parser.py from the REAL observation of that
# session) — never a static assumption per use case.
_CERT_UNAVAILABLE_LABELS = {
    "not_observable_tls13_encrypted_certificate": (
        "The certificate is not observable in this session: TLS 1.3 was negotiated, which encrypts "
        "the Certificate message — a structural property of the protocol, not a limitation of the "
        "data collection. A session of the same policy negotiating TLS 1.2 would make it observable."
    ),
}


def _compare_host_key(exp: dict, obs: dict) -> ComparisonResult:
    unavailable_reason = obs.get("host_key_unavailable_reason")
    if exp.get("host_key_algo") is not None and obs.get("host_key") is None and unavailable_reason:
        reason = _CERT_UNAVAILABLE_LABELS.get(
            unavailable_reason,
            f"The certificate was not observed in this session (reported reason: {unavailable_reason}).",
        )
        return _not_comparable(exp.get("host_key_algo"), None, "tiered_classification", reason)
    return cmp_tiered_classification(exp.get("host_key_algo"), obs.get("host_key"), cl.hostkey_level)


def _compare_has_pfs(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_boolean_implication(exp.get("has_pfs"), obs.get("has_pfs"))


def _compare_auth_method(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_set_membership(exp.get("auth_method"), obs.get("auth_method"))


# PQC posture comparator — explicit total order:
# native PQ > hybrid > classical.
# Both operands are produced by the SAME function
# (crypto_levels.kex_pq_posture) from the SAME field (kex): on the
# Expected side by graph_writer._derive_expected_pq_postures, on the
# Observed side by cbom_loader — never by the GUI, whose value is only a
# preview. The comparison is therefore symmetric by construction.
# The keys MUST be the exact PQReadiness values in schema.py (mirrored by
# PQ_POSTURE in app.js and by the POSTURE_* constants in crypto_levels.py):
# an unrecognized value would silently fall back to rank 0 below.
_PQ_POSTURE_RANK: dict[str, int] = {
    "classical": 0,
    "hybrid (classical+PQ)": 1,
    "native PQ": 2,
}

_PQ_POSTURE_CRITERION = "PQC posture total order (native PQ > hybrid > classical)"


def _compare_pq_readiness(exp: dict, obs: dict) -> ComparisonResult:
    exp_val = exp.get("pq_readiness")
    obs_val = obs.get("pq_readiness")
    if exp_val is None or obs_val is None:
        return _not_comparable(exp_val, obs_val, "ordinal_enum",
                               "PQC posture not available on one of the two sides")
    exp_rank = _PQ_POSTURE_RANK.get(exp_val, 0)
    obs_rank = _PQ_POSTURE_RANK.get(obs_val, 0)
    if obs_rank >= exp_rank:
        return ComparisonResult(
            status=MATCH, expected_value=exp_val, observed_value=obs_val,
            severity=0.0, comparator="ordinal_enum",
            criterion_label=_PQ_POSTURE_CRITERION,
            inequality=f"rank({obs_val})={obs_rank} ≥ rank({exp_val})={exp_rank}",
            exact_match=(obs_val == exp_val), detail=f"Observed posture ({obs_val}) ≥ expected ({exp_val})",
        )
    return ComparisonResult(
        status=DEVIATION, expected_value=exp_val, observed_value=obs_val,
        severity=round((exp_rank - obs_rank) / max(len(_PQ_POSTURE_RANK) - 1, 1), 2),
        comparator="ordinal_enum",
        criterion_label=_PQ_POSTURE_CRITERION,
        inequality=f"rank({obs_val})={obs_rank} < rank({exp_val})={exp_rank}",
        exact_match=False,
        detail=f"Observed posture ({obs_val}) lower than the expected one ({exp_val}): "
               f"the cryptographic primitives in use do not reach the PQC level required by the policy.",
    )


TLS_DIMENSIONS: dict[str, Callable[[dict, dict], ComparisonResult]] = {
    "protocol_version": _compare_protocol_version,
    "kex": _compare_kex,
    "cipher": _compare_cipher,
    "mac": _compare_mac,
    "host_key": _compare_host_key,
    "has_pfs": _compare_has_pfs,
    "auth_method": _compare_auth_method,
    "pq_readiness": _compare_pq_readiness,
}


# Before this revision there was a single GENERIC_DIMENSIONS shared by TLS
# and SSH, including has_pfs. Checked against cbom_loader.py: the SSH
# branch of _extract_profile NEVER sets has_pfs (it stays None by
# construction of the code, not for lack of a sample), and no SSH use case
# has ever had a GUI parameter to declare it — the comparison was
# therefore NOT_COMPARABLE for every SSH session, on both sides, always,
# not "often". Not just dead data: SSH does not even have a real
# equivalent of TLS's "static RSA without PFS" problem — every realistic
# KEX mechanism offered in the GUI (curve25519, ML-KEM hybrids, classic DH
# groups) is by construction an ephemeral exchange, there is no sensible
# option that denies it. The dimension never discriminates anything for
# this protocol family: removed from SSH_DIMENSIONS, not just left empty.
SSH_DIMENSIONS: dict[str, Callable[[dict, dict], ComparisonResult]] = {
    "protocol_version": _compare_protocol_version,
    "kex": _compare_kex,
    "cipher": _compare_cipher,
    "mac": _compare_mac,
    "host_key": _compare_host_key,
    "auth_method": _compare_auth_method,
    "pq_readiness": _compare_pq_readiness,
}


def dimensions_for_protocol(protocol: str | None) -> dict[str, Callable[[dict, dict], ComparisonResult]]:
    """Picks the comparator registry based on the protocol of the Observed
    node actually read from the graph (never a static per-use-case
    assumption: two assets of the same IPsec use case could, in theory,
    generate traffic of different families — see the historical fix on
    SSH/IPsec attribution in cbom_loader.py). A value other than "SSH"
    (including None, when the function is called before a real
    observation exists) falls back to TLS_DIMENSIONS: it is the behavior
    that predates this split, kept as the default so as not to introduce
    a silent regression elsewhere."""
    return SSH_DIMENSIONS if protocol == "SSH" else TLS_DIMENSIONS


# ─── IKE SA (IPsec control channel) ──────────────────────────────────────

def _compare_ike_protocol_version(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_ordinal_enum(exp.get("protocol_version"), obs.get("protocol_version"), _ike_version_rank)


def _compare_ike_kex(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_tiered_classification(exp.get("kex"), obs.get("kex"), cl.kex_level)


def _compare_ike_cipher(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_tiered_classification(exp.get("cipher"), obs.get("cipher"), cl.cipher_level)


def _compare_ike_mac(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_tiered_classification(exp.get("mac"), obs.get("mac"), lambda v: cl.mac_level(None, v))


def _normalize_ike_auth(val: str | None) -> str | None:
    """Normalizes the IKE auth_method to a comparable semantic category.
    strongSwan reports "pubkey"/"psk", the GUI declares readable strings —
    a normalization is needed to make the comparison epistemically grounded.
    """
    if val is None:
        return None
    v = val.lower()
    if "psk" in v or "pre-shared" in v:
        return "psk"
    if "falcon" in v:
        return "falcon"
    if "dilithium" in v or "crystals" in v:
        return "dilithium"
    if "ecdsa" in v or ("pubkey" in v and "rsa" not in v):
        return "pubkey_ecdsa"
    if "rsa" in v:
        return "pubkey_rsa"
    if "eap-tls" in v or ("eap" in v and "tls" in v):
        return "eap_tls"
    if "eap" in v:
        return "eap_other"
    if "pubkey" in v:
        return "pubkey_ecdsa"  # default pubkey → ECDSA (modern strongSwan default)
    return val.lower()


# PQC total order for IKE auth: native PQ > ECDSA/pubkey > PSK > RSA > weak EAP
_IKE_AUTH_RANK = {
    "falcon": 4, "dilithium": 4,
    "pubkey_ecdsa": 3,
    "eap_tls": 2,
    "psk": 2,
    "pubkey_rsa": 1,
    "eap_other": 0,
}

_IKE_AUTH_CRITERION = "IKE_AUTH authentication method (normalized)"


def _compare_ike_auth_method(exp: dict, obs: dict) -> ComparisonResult:
    exp_raw = exp.get("auth_method")
    obs_raw = obs.get("auth_method")
    exp_norm = _normalize_ike_auth(exp_raw)
    obs_norm = _normalize_ike_auth(obs_raw)
    if exp_norm is None or obs_norm is None:
        return _not_comparable(exp_raw, obs_raw, "set_membership",
                               "auth_method missing on one of the two sides")
    exp_rank = _IKE_AUTH_RANK.get(exp_norm, 1)
    obs_rank = _IKE_AUTH_RANK.get(obs_norm, 1)
    if obs_norm == exp_norm:
        return ComparisonResult(
            status=MATCH, expected_value=exp_raw, observed_value=obs_raw,
            severity=0.0, comparator="set_membership",
            criterion_label=_IKE_AUTH_CRITERION,
            inequality=f"{obs_norm} = {exp_norm}", exact_match=True,
            detail=f"IKE authentication method matches: {obs_raw}",
        )
    if obs_rank >= exp_rank:
        return ComparisonResult(
            status=MATCH, expected_value=exp_raw, observed_value=obs_raw,
            severity=0.0, comparator="set_membership",
            criterion_label=_IKE_AUTH_CRITERION,
            inequality=f"rank({obs_norm})={obs_rank} ≥ rank({exp_norm})={exp_rank}",
            exact_match=False,
            detail=f"Observed method ({obs_raw}) at least equivalent to the expected one ({exp_raw})",
        )
    return ComparisonResult(
        status=DEVIATION, expected_value=exp_raw, observed_value=obs_raw,
        severity=round(min(1.0, (exp_rank - obs_rank) / max(len(_IKE_AUTH_RANK), 1)), 2),
        comparator="set_membership",
        criterion_label=_IKE_AUTH_CRITERION,
        inequality=f"rank({obs_norm})={obs_rank} < rank({exp_norm})={exp_rank}",
        exact_match=False,
        detail=f"Observed IKE authentication method ({obs_raw}) lower than the expected one ({exp_raw}): "
               f"the cryptographic proof of identity does not reach the level declared in the policy.",
    )


def _compare_ike_rekey_time(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_numeric_min_better(exp.get("rekey_time_seconds"), obs.get("rekey_time_seconds"))


# Deliberate note: mutual_auth does not appear here. In IKEv2 both sides
# always authenticate each other by protocol construction — unlike TLS,
# where server-only vs mutual is a real deployment choice, here it would
# be a trivially always-true comparison, with no informative value.
# Including it only for symmetry with the generic profile would be noise,
# not rigor.
IKE_SA_DIMENSIONS: dict[str, Callable[[dict, dict], ComparisonResult]] = {
    "protocol_version": _compare_ike_protocol_version,
    "kex": _compare_ike_kex,
    "cipher": _compare_ike_cipher,
    "mac": _compare_ike_mac,
    "auth_method": _compare_ike_auth_method,
    "rekey_time_seconds": _compare_ike_rekey_time,
    # Present since the posture became a key-exchange property: before, the
    # Observed IKE SA carried a pq_readiness that was computed, stored and
    # never compared (this registry had no entry for it), while the
    # generic profile — the only one with a pq_readiness comparator — is
    # skipped for IPsec. IPsec was the one protocol family whose posture
    # was never evaluated against the policy.
    "pq_readiness": _compare_pq_readiness,
}


# ─── Child SA (ESP data channel) ─────────────────────────────────────────

def _compare_child_cipher(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_tiered_classification(exp.get("cipher"), obs.get("cipher"), cl.cipher_level)


def _compare_child_dh_group(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_tiered_classification(exp.get("dh_group"), obs.get("dh_group"), cl.kex_level)


def _compare_child_pfs_capable(exp: dict, obs: dict) -> ComparisonResult:
    """Compares the PFS requirement declared in the policy (exp.pfs_capable,
    the expected side, set in the GUI) against what was actually observed
    in this sample (obs.pfs_observed, sourced from has_pfs).

    BUGFIX: this previously compared exp.pfs_capable against
    obs.pfs_capable. obs.pfs_capable is NOT a runtime observation — in
    cbom_loader._extract_child_sa_profile it is populated from the
    artifact's own declared_pfs_capable field, i.e. the connection's own
    declared configuration, echoed back by the collector. Comparing
    exp.pfs_capable (declared in the GUI) against obs.pfs_capable
    (declared in the artifact) is therefore a declared-vs-declared
    comparison: both sides normally agree by construction, since they
    describe the same configuration intent from two sources, never the
    true negotiated state. This made a genuine, persistent absence of PFS
    (has_pfs=False on a rekeyed Child SA) structurally undetectable — it
    always evaluated as MATCH regardless of what was actually negotiated.

    The one valid reason to avoid comparing against the raw observation
    directly is that the very first Child SA of an IKE_SA never carries a
    KE payload by protocol construction (RFC 7296: IKE_AUTH negotiates the
    first Child SA without a fresh Diffie-Hellman exchange), so
    has_pfs=False is structural, not a violation, on that specific sample.
    This case is already distinguished elsewhere in the profile by the
    absence of esp_group/dh_group (see _extract_child_sa_profile), so it
    is used here as the discriminator: when dh_group is unset, the sample
    predates any Child SA rekey and PFS cannot be meaningfully evaluated
    (NOT_COMPARABLE); once a dh_group is present, pfs_observed reflects a
    real rekey attempt and is compared against the declared policy."""
    if obs.get("dh_group") is None:
        reason = ("The first Child SA of an IKE_SA carries no KE payload by protocol "
                  "construction (RFC 7296) — PFS cannot be evaluated on this sample; "
                  "a later rekey is required before this dimension becomes comparable.")
        return _not_comparable(exp.get("pfs_capable"), obs.get("pfs_observed"),
                                "boolean_implication", reason)
    return cmp_boolean_implication(exp.get("pfs_capable"), obs.get("pfs_observed"))


def _compare_child_lifetime(exp: dict, obs: dict) -> ComparisonResult:
    return cmp_numeric_min_better(exp.get("lifetime_seconds"), obs.get("lifetime_seconds"))


CHILD_SA_DIMENSIONS: dict[str, Callable[[dict, dict], ComparisonResult]] = {
    "cipher": _compare_child_cipher,
    "dh_group": _compare_child_dh_group,
    "pfs_capable": _compare_child_pfs_capable,
    "lifetime_seconds": _compare_child_lifetime,
}