# =====================================================================
# CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
# schema.py — Application domain vocabulary
#
# This module is the Python counterpart of the "1. DOMAIN VOCABULARY"
# block in the Cypher script. While Neo4j imposes no structure on nodes
# beyond uniqueness constraints, this file defines EXACTLY which
# properties are allowed for each entity and with which types/values.
# It is the single point where the conceptual schema is enforced before
# any data reaches the graph.
#
# Every payload coming from the GUI goes through these models. If the
# payload does not match the expected shape, Pydantic raises a
# ValidationError and FastAPI automatically turns it into an HTTP 422
# response — corrupted data never reaches Neo4j.
#
# UPDATE — Lifecycle & Data Governance: the vocabulary has been extended
# with DataSensitivity, PQReadiness and the corresponding fields on
# ExpectedCryptoProfile (data_sensitivity, pq_readiness), as well as
# shelf_time_days, now exposed in the GUI. See quantum_risk.py for how
# shelf time and the key-exchange posture produce the harvest-now-decrypt-
# later exposure written on the UseCase node, on BOTH sides:
# quantum_risk_expected_flag (policy) and quantum_risk_observed_flag
# (worst key exchange over every observed session). The use-case criticality (suggested_criticality) is
# now selected directly by the operator in the GUI, no longer derived
# implicitly.
#
# UPDATE — English vocabulary: the enum VALUES below (not only the
# comments) are the exact strings the GUI sends (data.js / app.js). They
# MUST stay byte-for-byte identical on both sides: a mismatch is not a
# cosmetic issue, it is an HTTP 422 on every save. The mirrors to keep in
# sync by hand are:
#   DataSensitivity  ↔ governance "data_sensitivity" options in data.js
#                     ↔ GOVERNANCE_RISK_MATRIX in app.js
#                     ↔ _GOVERNANCE_RISK_MATRIX in graph_writer.py
#   PQReadiness      ↔ PQ_POSTURE in app.js
#                     ↔ POSTURE_* in crypto_levels.py
#                     ↔ _PQ_POSTURE_RANK in comparators.py
# =====================================================================

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


# ─── DOMAIN ENUMERATIONS ────────────────────────────────────────────────
# These values are not arbitrary: they match what is actually supported
# by the reference implementations (StrongSwan for IPsec, OpenSSH for
# SSH, standard TLS libraries). Any value outside these lists is
# rejected at validation time, before Neo4j.

class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Zone(str, Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL_LAN = "internal_lan"
    MGMT = "mgmt"
    SERVICE_MESH = "service_mesh"
    VPN_TUNNEL = "vpn_tunnel"
    REMOTE_SITE = "remote_site"


# ─── DATA GOVERNANCE AND POST-QUANTUM POSTURE ───────────────────────────
# Introduced to increase the granularity of the Expected profile beyond
# purely algorithmic parameters. Unlike the previous enumerations, they
# are not constraints imposed by the reference libraries
# (StrongSwan/OpenSSH/TLS) but data-governance categories: how long the
# data protected by this use case must stay confidential (shelf time, see
# UseCaseInput.shelf_time_days) and how robust it is against an adversary
# equipped with a quantum computer (pq_readiness).
#
# Comparing shelf_time_days and pq_readiness is the basis of the
# "harvest-now, decrypt-later" reasoning formalized by Mosca's theorem
# (X + Y > Z): if the data must stay protected longer than it takes an
# adversary to break classical encryption once a relevant quantum
# computer is available, the configuration is at risk even if it complies
# with today's classical standards. See graph_writer.py for the
# (heuristic, simplified) computation of the risk flag derived from these
# two parameters.

class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"


class PQReadiness(str, Enum):
    CLASSICAL = "classical"
    HYBRID = "hybrid (classical+PQ)"
    NATIVE_PQ = "native PQ"


# ─── ASSET ──────────────────────────────────────────────────────────────

class AssetInput(BaseModel):
    """
    Maps to the :Asset node.
    Properties: name, zone, criticality (+ ip, hostname as identifying
    metadata collected by the GUI, useful for the join with Zeek logs).
    """
    name: str = Field(..., min_length=1, description="Unique asset identifier, e.g. 'vpnlocal'")
    role: str = Field(..., description="Role description, e.g. 'Local VPN endpoint'")
    zone: Zone
    criticality: Criticality
    ip: IPvAnyAddress
    hostname: str = Field(..., min_length=1)

    @field_validator("name")
    @classmethod
    def name_no_spaces(cls, v: str) -> str:
        if " " in v:
            raise ValueError("The asset name cannot contain spaces (it is used as a key in the graph)")
        return v


# ─── EXPECTED CRYPTO PROFILE — per use case ────────────────────────────
# Mirrors exactly the fields listed in the "MAIN PROPERTIES PER ENTITY"
# block of the Cypher file for Expected. All optional at the Python type
# level because — as the note in that file specifies — not every
# attribute is relevant to every use case (e.g. mutual_auth makes no
# sense for SSH). Omission is handled by excluding the field on write
# (exclude_none), not by writing null.

class ExpectedCryptoProfile(BaseModel):
    protocol_version: Optional[str] = None      # e.g. "IKEv2", "TLS 1.3", "SSHv2"
    cipher: Optional[str] = None                # e.g. "AES-256-GCM"
    kex: Optional[str] = None                   # e.g. "ECP384 (gr20)", "curve25519-sha256"
    host_key_algo: Optional[str] = None         # e.g. "Ed25519", "ECDSA P-384"
    auth_method: Optional[str] = None           # e.g. "Public key", "mTLS"
    mutual_auth: Optional[bool] = None
    client_cert_required: Optional[bool] = None
    cert_rotation_hours: Optional[int] = Field(None, ge=0)
    # Relevant for SSH (e.g. "hmac-sha2-256-etm") and for the IKE SA, where
    # the MAC/PRF is negotiated as an independent parameter. For TLS it must
    # NOT be filled in: the MAC is a deterministic consequence of the cipher
    # suite (AEAD in TLS 1.2 with GCM/Poly1305, mandatory in TLS 1.3) and is
    # not a separate degree of freedom to declare — comparators._compare_mac
    # derives it directly from `cipher` for this protocol. The field simply
    # stays empty for TLS use cases, not through omission.
    mac: Optional[str] = None
    has_pfs: Optional[bool] = None              # required by comparators.cmp_boolean_implication

    # ── Lifecycle & Data Governance ────────────────────────────────────
    # Fields added to increase the granularity of the expected profile
    # beyond purely algorithmic parameters. pq_readiness is accepted from
    # the GUI for validation only: graph_writer recomputes it from `kex`
    # before writing (see _derive_expected_pq_postures), so the value in
    # the graph never depends on the client.
    #
    # NOTE: a generalized key-rotation field (key_rotation_hours) was
    # initially introduced here next to data_sensitivity/pq_readiness, but
    # it has been removed: in a short-lived simulation environment
    # (Kathará + Zeek, a session of a few minutes/hours) a real rotation
    # interval can be neither observed nor reliably estimated, so the
    # parameter would have been a declared value not verifiable by the
    # detection pipeline — at odds with the system's design, in which
    # every expected property should be comparable with an observation
    # (see the VIOLATES relationship). cert_rotation_hours instead stays
    # unchanged: it is specific to use cases with automatically rotated
    # certificates (mTLS/service mesh) and is fed by an explicit
    # cryptographic parameter ("Cert. rotation"), not by a generic estimate.
    data_sensitivity: Optional[DataSensitivity] = None
    pq_readiness: Optional[PQReadiness] = None

    def to_neo4j_props(self) -> dict:
        """
        Excludes unset fields: no null properties are written on the node.
        mode="json" forces Enum fields (data_sensitivity, pq_readiness) to
        be converted to their primitive string value: the Bolt driver
        requires native types, not Enum instances, even when the Enum
        inherits from str (see note in graph_writer.write_usecase).
        """
        return self.model_dump(exclude_none=True, mode="json")


# ─── POLICY ─────────────────────────────────────────────────────────────

class PolicyInput(BaseModel):
    name: str
    description: str = ""


# ─── OBSERVED CRYPTO PROFILE — per (asset, use case), from pipeline_cbom ──
# Maps to the :CryptoProfile:Observed node. Same conceptual idea as
# Expected — cryptographic properties of an asset — but with an
# epistemic difference that must be preserved in the schema too: every
# field here reflects data OBSERVED on real traffic (via cbom_loader.py,
# fed by pipeline_cbom.py), never declared by an operator. The
# observed_key field is the uniqueness key (asset + use case): a new
# ingest overwrites the previous observed profile for the same pair,
# reflecting the most recent observed state — not a historical log of
# every session (which remains fully available in cbom.json, upstream).

class ObservedCryptoProfile(BaseModel):
    protocol_version: Optional[str] = None      # e.g. "TLSv13" — never comparable before comparators.py
    kex: Optional[str] = None
    cipher: Optional[str] = None
    mac: Optional[str] = None
    host_key: Optional[str] = None
    auth_method: Optional[str] = None
    protocol: Optional[str] = None
    has_pfs: Optional[bool] = None
    # Why host_key is absent, when it is — taken directly from the
    # cert_observation_method field already present in cbom.json (produced
    # by pipeline_cbom/tls_parser.py), never inferred or assumed here. For
    # TLS 1.3 it is always "not_observable_tls13_encrypted_certificate" —
    # but it is a FACT about this specific session, not a static assumption
    # about the use case: the same policy, with a client negotiating
    # TLS 1.2, would produce an observable value in another session.
    host_key_unavailable_reason: Optional[str] = None
    # PQC posture of the observed KEY EXCHANGE — not declared. Computed by
    # crypto_levels.kex_pq_posture(kex), the same function graph_writer
    # applies to the Expected kex: a symmetric comparison by construction.
    pq_readiness: Optional[str] = None

    # Provenance — never present on Expected, mandatory in spirit here
    # (optional only at the type level to tolerate incomplete data): an
    # observed profile without knowing FROM WHICH sensor and WHEN would
    # lose the traceability the whole pipeline is built on.
    sensor_id: Optional[str] = None
    ts: Optional[float] = None
    uid: Optional[str] = None

    def to_neo4j_props(self) -> dict:
        return self.model_dump(exclude_none=True, mode="json")


# ─── IKE SA / CHILD SA — the two distinct cryptographic layers of IPsec ────
# An IPsec/IKEv2 VPN does not have ONE cryptographic profile, it has two,
# negotiated separately, which may legitimately differ:
#   - IKE SA: the control channel. Authenticates the two endpoints and
#     protects the negotiation itself. Properties: IKE version,
#     encryption/MAC/KEX OF THIS channel, authentication method, mutual auth.
#   - Child SA: the data channel (ESP). Protects the actual application
#     traffic. Its own properties: ESP encryption (often different from
#     the IKE one), DH group used for PFS (never present on the very first
#     Child SA, by protocol construction — see the pfs_observed field),
#     lifetime, mode.
# Merging the two into a single CryptoProfile node — as the first version
# of this schema did — means unknowingly comparing the declared
# control-channel encryption with the observed data-channel encryption:
# apples and oranges, a real bug found precisely for this reason.

class IkeSaCryptoProfile(BaseModel):
    protocol_version: Optional[str] = None      # "IKEv2", "IKEv1 (deprecated)"
    cipher: Optional[str] = None                # e.g. "AES_GCM_16-256"
    mac: Optional[str] = None                   # the PRF — e.g. "HMAC_SHA2_384"
    kex: Optional[str] = None                   # DH group of THIS negotiation — e.g. "ECP_384"
    auth_method: Optional[str] = None           # "PSK (Pre-Shared Key)" | "X.509 certificates (EAP-TLS)"
    mutual_auth: Optional[bool] = None           # do both sides authenticate with the same method?
    rekey_time_seconds: Optional[int] = None
    # pq_readiness: derived from kex (IKE_SA_INIT group + any RFC 9370
    # additional key exchanges) by crypto_levels.kex_pq_posture, on both
    # the Expected and the Observed IKE SA; compared by
    # comparators._compare_pq_readiness through IKE_SA_DIMENSIONS.
    pq_readiness: Optional[str] = None

    # Provenance, only for Observed instances (absent on Expected)
    sensor_id: Optional[str] = None
    ts: Optional[float] = None
    uid: Optional[str] = None

    def to_neo4j_props(self) -> dict:
        return self.model_dump(exclude_none=True, mode="json")


class ChildSaCryptoProfile(BaseModel):
    cipher: Optional[str] = None                 # ESP encryption — e.g. "AES_GCM_16-256"
    dh_group: Optional[str] = None                # DH group for PFS — present ONLY after a rekey
    pfs_capable: Optional[bool] = None            # (Expected/declared side) does the ESP proposal include a DH group?
    pfs_observed: Optional[bool] = None           # (Observed side) was PFS observed in THIS sample?
    lifetime_seconds: Optional[int] = None
    mode: Optional[str] = None                    # "tunnel" | "transport"

    sensor_id: Optional[str] = None
    ts: Optional[float] = None
    uid: Optional[str] = None

    def to_neo4j_props(self) -> dict:
        return self.model_dump(exclude_none=True, mode="json")


# ─── USE CASE — the atomic semantic unit ───────────────────────────────

class UseCaseInput(BaseModel):
    """
    Maps to the :UseCase node. Aggregates Policy, Expected and the
    involved Assets: it is the payload the GUI sends in a single POST when
    the administrator presses "Save policy".
    """
    name: str = Field(..., min_length=1)
    shelf_time_days: int = Field(
        0, ge=0,
        description=(
            "Retention/exposure horizon of the protected data, in days. "
            "Exposed and configurable in the GUI (Cryptographic parameters tab, "
            "Lifecycle & Data Governance section): it is parameter X of the "
            "harvest-now-decrypt-later reasoning. It is an attribute of the use "
            "case (the data it protects), not of either cryptographic profile, "
            "and cannot be inferred from telemetry: it is combined, with the same "
            "heuristic (quantum_risk.py), with both the expected and the worst "
            "observed key-exchange posture."
        ),
    )
    suggested_criticality: Criticality
    rationale: str = ""

    policy: PolicyInput
    expected: ExpectedCryptoProfile
    assets: list[AssetInput] = Field(..., min_length=1)

    # Present only for IPsec use cases (VPN Road Warrior, Site-to-Site) —
    # the control channel (IKE SA) and the data channel (Child SA) have
    # cryptographic proposals negotiated separately, often different from
    # each other: merging them into a single Expected/Observed profile, as
    # the first version of this schema did, produced an incorrect
    # comparison (declared IKE encryption against observed ESP
    # encryption). For every other use case these two fields stay None and
    # produce no additional write — no change to the existing behavior for
    # TLS/SSH.
    ike_sa: IkeSaCryptoProfile | None = None
    child_sa: ChildSaCryptoProfile | None = None

    # ── SSH ProxyJump — cryptographic context #2 ───────────────────────
    # Present only for the SSH Bastion Access (ProxyJump) use case.
    # expected2 carries the Expected profile for the second SSH hop:
    # ClientExt ↔ AppServer (end-to-end, with the bastion as TCP forwarder).
    # If absent, the use case is treated as standard two-node SSH.
    is_bastion_proxyjump: bool = False
    expected2: ExpectedCryptoProfile | None = None

    service_name: str
    service_protocol: str
    # Clean protocol family (e.g. "ipsec"/"ssh"/"tls"), distinct from the
    # free-form description service_protocol (e.g. "IPsec / IKEv2 —
    # StrongSwan"). Needed to fix a real bug: an asset such as clientext,
    # declared for VPN Road Warrior (IPsec), ALSO generates SSH traffic
    # (through the tunnel, towards the bastion) — without this field,
    # cbom_loader.py attributed that SSH record to the same IPsec use case
    # just because the asset name matched, producing a comparison between
    # profiles of different protocols.
    service_protocol_family: str = Field(..., min_length=1)


# ─── STANDARD API RESPONSE ─────────────────────────────────────────────

class WriteResult(BaseModel):
    status: str
    usecase: str
    assets_written: int
    nodes_touched: int
