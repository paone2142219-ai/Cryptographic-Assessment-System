// ─── DATA MODEL ─────────────────────────────────────────────────────────────
// All use cases with parameters, assets, governance and demo findings.
// Real findings are injected by the Zeek → ETL → Neo4j pipeline.
//
// UPDATE — Governance review:
//   • Removed the "Compliance" section (NIST/BSI/RFC badges): no longer
//     tracked at use-case level in this iteration of the project.
//   • Removed the generalized key rotation parameter
//     (key_rotation_hours) from the Lifecycle & Data Governance card: it
//     cannot be reliably estimated in a short-lived Kathará simulation
//     (see note in schema.py).
//   • Removed the "Observability" parameter from the Service Mesh use case:
//     redundant, the only observation tool in the pipeline is Zeek.
//   • Added "Use-case criticality" to the Lifecycle & Data Governance
//     card: previously derived implicitly, now explicitly selectable by
//     the operator (options: low/medium/high, as Criticality in schema.py).
//   • Added the "VPN Road Warrior" use case (IPsec/IKEv2, PSK,
//     clientext ↔ mainfw).
//
// UPDATE — Consistency of TLS cryptographic menus (KEX/cipher parameters):
//   • The "KEX curve/group" parameter, where present in TLS use cases, is
//     never redundant with the cipher suite in general (the suite name
//     encodes only the MECHANISM — ECDHE/DHE/static RSA — never the
//     specific group, negotiated separately in supported_groups/key_share,
//     in both TLS 1.2 and TLS 1.3), but it becomes redundant, and
//     meaningless, when the chosen mechanism is static RSA key transport:
//     in that case there is no Diffie-Hellman to negotiate.
//     tlsCurveOptionsFor() now applies the same principle already used by
//     tlsCipherOptionsFor(), conditioning the available options on the
//     mechanism implied by the selected cipher suite, instead of an
//     always-open menu.
//   • All TLS use cases (api_gateway_tls13, service_mesh, mail_tls,
//     syslog_tls) now use the same shared TLS12/TLS13_CIPHER_OPTIONS lists
//     via tlsCipherOptionsFor()/tlsCipherRecommendedFor(), no longer local
//     static lists: before this update, mail_tls (cipher12 field) never
//     exposed TLS 1.3 suites despite having "TLS 1.3 + 1.2" as its default
//     option, and syslog_tls mixed TLS 1.2 and TLS 1.3 naming in the same
//     static list together with a static RSA suite, regardless of the TLS
//     version actually chosen.
//   • TLS12_CIPHER_OPTIONS extended with DHE (non-elliptic-curve), static
//     RSA AEAD and CBC-SHA256 variants — TLS13_CIPHER_OPTIONS unchanged:
//     it already includes all 5 cipher suites that exist for TLS 1.3
//     (RFC 8446 §B.4), not an arbitrary, extensible selection.

// ─── TLS CIPHER SUITES — shared lists per protocol version ─────────────────
// TLS 1.3 has only 5 cipher suites in total (RFC 8446 §B.4) — not an
// arbitrary choice of which to include, they are all the ones that exist.
// Exact IANA naming: "TLS_CHACHA20_POLY1305_SHA256", not
// "TLS_CHACHA20_POLY1305" (the hash suffix was missing in an earlier
// version of this file — an incomplete name, not a valid abbreviation).
const TLS13_CIPHER_OPTIONS = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_128_CCM_SHA256 (IoT/constrained use)",
  "TLS_AES_128_CCM_8_SHA256 (⚠ authentication tag truncated to 8 bytes)",
];

// TLS 1.2: classic IANA naming (TLS_<kex>_<auth>_WITH_<cipher>_<hash>),
// not the hyphenated OpenSSL style — never observed on the wire by Zeek.
// Extended (see update note at the top of the file) with finite-field DHE
// variants (PFS without elliptic curves), static RSA AEAD and CBC-SHA256
// — in addition to the ECDHE/AEAD and legacy suites already present. Every
// entry remains classifiable without changes to crypto_levels.py:
// cipher_level() and mac_level() work by pattern (aes/chacha20 + length +
// cbc/gcm/hash suffix), not by an exhaustive table of strings.
const TLS12_CIPHER_OPTIONS = [
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (⚠ non-AEAD)",
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (⚠ non-AEAD)",
  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (DHE — finite-field PFS, not elliptic-curve)",
  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (DHE — finite-field PFS, not elliptic-curve)",
  "TLS_RSA_WITH_AES_256_GCM_SHA384 (⚠ static RSA — no PFS)",
  "TLS_RSA_WITH_AES_256_CBC_SHA (⚠ non-AEAD, non-ECDHE)",
  "TLS_RSA_WITH_AES_128_CBC_SHA (⚠ non-AEAD, non-ECDHE)",
  "TLS_RSA_WITH_3DES_EDE_CBC_SHA (broken)",
];

function tls13Only(sel) {
  const v = sel.tls_ver || "";
  return v.includes("1.3") && !v.includes("1.2");
}
function tls12Only(sel) {
  const v = sel.tls_ver || "";
  // TLS 1.0/1.1/1.2 share the same identifier space and the same IANA
  // cipher suite naming (TLS_<kex>_<auth>_WITH_...); only TLS 1.3
  // (RFC 8446) introduced a radically different naming and suite set.
  // An option such as "TLS 1.1 or lower (⚠)" (see syslog_tls) therefore
  // falls into the same namespace as "TLS 1.2 only", not into TLS 1.3's —
  // before this update it was not recognized by this function, and fell
  // into the "indiscriminate union" fallback branch even when a precise
  // version had been selected.
  return (v.includes("1.2") || v.includes("1.1") || v.includes("1.0")) && !v.includes("1.3");
}
// Cipher options depending on the selected TLS version — TLS 1.2 and
// TLS 1.3 share NO cipher suite (naming and protocol construction changed
// radically in TLS 1.3): showing the indiscriminate union of the two lists
// would allow "configuring" a combination the protocol can never produce.
function tlsCipherOptionsFor(sel) {
  if (tls13Only(sel)) return TLS13_CIPHER_OPTIONS;
  if (tls12Only(sel)) return TLS12_CIPHER_OPTIONS;
  return [...TLS13_CIPHER_OPTIONS, ...TLS12_CIPHER_OPTIONS]; // "TLS 1.3 + 1.2"
}
function tlsCipherRecommendedFor(sel) {
  return tls12Only(sel) ? "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" : "TLS_AES_256_GCM_SHA384";
}

// ─── TLS KEY EXCHANGE (KEX) — group/curve, independent of the cipher suite ──
// The cipher suite name indicates ONLY the key exchange mechanism
// (ephemeral elliptic-curve ECDHE / ephemeral finite-field DHE / static RSA
// key transport), never the specific group or curve — those travel in the
// supported_groups/key_share extension, negotiated independently, in both
// TLS 1.2 and TLS 1.3 (see cbom_loader.py: rec.get("curve") is a Zeek field
// distinct from rec.get("cipher")). The parameter is therefore NOT
// redundant with the cipher suite in general — it only becomes so when the
// chosen mechanism involves no Diffie-Hellman exchange at all (static RSA),
// or involves a finite-field group instead of a curve (DHE): in both cases
// still offering a menu of selectable elliptic curves would allow
// configuring a combination the chosen cipher suite can never produce —
// the same principle already applied by tlsCipherOptionsFor for the TLS
// version, applied here to the key exchange mechanism implied by the
// cipher suite.
const TLS_CURVE_OPTIONS = [
  // ── Classical ─────────────────────────────────────────
  "x25519",
  "secp384r1",
  "secp256r1",
  "secp521r1",
  "secp224r1 (⚠)",
  // ── Classical+PQ hybrids (IETF draft / NIST SP 800-227) ─
  "X25519MLKEM768 (hybrid PQ)",    // quantum-safe
  "X25519MLKEM1024 (hybrid PQ)",   // quantum-safe
  "P256MLKEM768 (hybrid PQ)",      // quantum-safe
  "P384MLKEM1024 (hybrid PQ)",     // quantum-safe
  "X25519Kyber768Draft00 (hybrid PQ)",  // quantum-safe — legacy draft (Cloudflare/Google)
];
// Constant used by renderParams ONLY to color PQ-related options green in
// the menus (KEM and signatures alike). It plays NO role in the PQC posture:
// that is derived from the key exchange alone by kexPQPosture() in app.js,
// mirroring crypto_levels.kex_pq_posture() in the backend.
const QUANTUM_SAFE_MARKERS = [
  // Classical+PQ hybrids (KEX)
  "hybrid PQ", "MLKEM", "mlkem", "KYBER", "sntrup", "BIKE", "HQC",
  // Native PQ signatures
  "FALCON", "DILITHIUM", "CRYSTALS", "SPHINCS", "XMSS",
  // Generic markers
  "native PQ",
];

const TLS_CURVE_NA_STATIC_RSA = [
  "Not applicable — static RSA key transport: no Diffie-Hellman negotiated, no PFS",
];
const TLS_CURVE_NA_DHE_FINITE_FIELD = [
  "Not applicable in this GUI — PFS over a finite-field DH group (not elliptic-curve); no dedicated parameter for MODP groups on the TLS side",
];
function tlsKeyExchangeMechanism(sel) {
  const c = sel.cipher || sel.cipher12 || "";
  if (/^TLS_RSA_WITH_/.test(c)) return "static_rsa";
  if (/^TLS_DHE_RSA_WITH_/.test(c)) return "dhe_finite_field";
  // Every ECDHE_* suite (TLS 1.2) and every TLS 1.3 suite (never a
  // mechanism prefix in the name, by construction: the ephemeral group is
  // always elliptic-curve or hybrid, never static key transport) lands here.
  return "ecdhe_or_tls13";
}
function tlsCurveOptionsFor(sel) {
  const mech = tlsKeyExchangeMechanism(sel);
  if (mech === "static_rsa") return TLS_CURVE_NA_STATIC_RSA;
  if (mech === "dhe_finite_field") return TLS_CURVE_NA_DHE_FINITE_FIELD;
  return TLS_CURVE_OPTIONS;
}
function tlsCurveRecommendedFor(sel) {
  const mech = tlsKeyExchangeMechanism(sel);
  if (mech === "static_rsa") return TLS_CURVE_NA_STATIC_RSA[0];
  if (mech === "dhe_finite_field") return TLS_CURVE_NA_DHE_FINITE_FIELD[0];
  return "x25519";
}

// ─── SERVER CERTIFICATE (algorithm) — observable only in TLS ≤1.2 ─────────
// The Certificate message is encrypted by construction in TLS 1.3
// (RFC 8446), not because of a pipeline limitation: if the negotiated
// version is "TLS 1.3 only", no session can ever reveal the certificate
// algorithm to Zeek — the field becomes non-configurable, the same
// treatment already applied by tlsCurveOptionsFor for an incompatible KEX
// mechanism. With "TLS 1.2 only" it remains fully selectable and comparable.
const TLS_CERT_OPTIONS = ["ecdsa-384", "ecdsa-256", "rsa-4096", "rsa-2048 (⚠)"];
const TLS_CERT_NA_TLS13 = [
  "Not applicable — TLS 1.3 encrypts the Certificate message by construction (RFC 8446)",
];
function tlsCertOptionsFor(sel) {
  return tls13Only(sel) ? TLS_CERT_NA_TLS13 : TLS_CERT_OPTIONS;
}
function tlsCertRecommendedFor(sel) {
  return tls13Only(sel) ? TLS_CERT_NA_TLS13[0] : "ecdsa-384";
}

const USE_CASES = [
  {
    id: "vpn_road_warrior",
    navIcon: "ti-device-laptop",
    protoFamily: "ipsec",
    name: "VPN Road Warrior",
    proto: "IPsec / IKEv2 — remote access ",
    // Remote access for mobile users: mainfw acts as VPN concentrator,
    // authenticates via PSK and dynamically assigns the IP from one of two
    // pools (administrator / employee), enabling differentiated IP-based
    // ACLs: employee → DMZ only; administrator → mgmt/bastion as well.
    params: [
      {
        label: "IKE version", key: "ike_version",
        options: ["IKEv2", "IKEv1 (deprecated)"],
        recommended: "IKEv2"
      },
      {
        label: "IKE_AUTH authentication method", key: "auth_method",
        // Cryptographic proof of identity during IKE_AUTH — distinct from
        // KEX (which provides confidentiality) and from channel encryption.
        // PSK: symmetric shared secret — not scalable, provides no
        //   verifiable individual authenticity (anyone knowing the PSK can impersonate).
        // X.509 RSA certificates: classical PKI — vulnerable to Shor (RSA public key).
        // X.509 ECDSA certificates: elliptic-curve PKI — vulnerable to Shor.
        // EAP-TLS: EAP authentication based on client-side X.509 certificates.
        // EAP-MSCHAPv2: username/password credentials — not cryptographically robust.
        // FALCON-512 / DILITHIUM: native post-quantum signatures — experimental on strongSwan.
        options: [
          "PSK (Pre-Shared Key)",
          "X.509 certificates — ECDSA (recommended)",
          "X.509 certificates — RSA-2048 (⚠ vulnerable to Shor)",
          "EAP-TLS (client-side X.509 certificates)",
          "EAP-MSCHAPv2 (⚠ weak credentials)",
          "FALCON-512 (native PQ — experimental)",
          "CRYSTALS-Dilithium (native PQ — experimental)",
        ],
        recommended: "X.509 certificates — ECDSA (recommended)"
      },
      {
        label: "Phase 1 encryption (IKE)", key: "enc1",
        // Real swanctl runtime format (AES_GCM_16-<bits>), the same that
        // pipeline_cbom reports in ike_enc/ike_enc_bits — not a generic
        // "readable" string: here the Observed comparison can also work by
        // exact equality, not only by level.
        options: ["AES_GCM_16-256", "AES_GCM_16-128", "CHACHA20_POLY1305 (hybrid PQ-ready)", "AES_CBC-256 (⚠ non-AEAD)", "3DES-CBC (broken)"],
        recommended: "AES_GCM_16-256"
      },
      {
        label: "Phase 1 PRF (integrity)", key: "int1",
        // ike_prf is a DISTINCT field from encryption in cbom.json
        // (e.g. "HMAC_SHA2_384") — before this revision it was confused
        // with the encryption itself, never actually compared.
        options: ["HMAC_SHA2_384", "HMAC_SHA2_256", "HMAC_SHA1 (⚠)", "HMAC_MD5 (broken)"],
        recommended: "HMAC_SHA2_384"
      },
      {
        label: "Phase 1 key exchange (IKE)", key: "dh1",
        // Hybrid options use the RFC 9370 composite notation
        // "<IKE_SA_INIT group>+<additional KE>": in IKEv2 a post-quantum KEM
        // is negotiated as an ADDITIONAL key exchange on top of a classical
        // IKE_SA_INIT group, never alone — and cbom_loader builds the observed
        // kex in exactly this form from swanctl ("ECP_384/KE1_ML_KEM_768" →
        // "ECP_384+ML_KEM_768"). Before, the options were the bare KEM names
        // ("KYBER_L3"), which a name-based classifier reads as a pure PQ KEX:
        // the "(hybrid PQ)" label was the only thing saying otherwise, and the
        // posture must never be read from a label (see kexPQPosture in app.js).
        options: ["ECP_384", "ECP_256", "ECP_521",
                  "ECP_384+ML_KEM_768 (hybrid PQ)", "ECP_384+KYBER_L3 (hybrid PQ)", "ECP_521+KYBER_L5 (hybrid PQ)",
                  "ECP_384+BIKE_L3 (hybrid PQ)", "ECP_384+HQC_L3 (hybrid PQ)",
                  "MODP_4096", "MODP_2048", "MODP_1024 (⚠)"],
        recommended: "ECP_384"
      },
      {
        label: "ESP encryption (data plane)", key: "enc2",
        options: ["AES_GCM_16-256", "AES_GCM_16-128", "AES_CBC-256 (⚠ non-AEAD)"],
        recommended: "AES_GCM_16-256"
      },
      {
        label: "PFS (phase 2 / rekey)", key: "pfs",
        // Consistent with what is actually observed in the lab: the very
        // first Child SA never carries a DH group by protocol construction
        // (IKE_AUTH carries no KE payload) — PFS is observable only after
        // a rekey, never in the initial sampling.
        options: ["ECP_384 (group dedicated to rekey)", "ECP_256 (group dedicated to rekey)", "Disabled — no group in ESP proposal (⚠)"],
        recommended: "ECP_384 (group dedicated to rekey)"
      },
      {
        label: "IKE SA rekey time (s)", key: "ike_rekey_time",
        // Compared by IKE_SA_DIMENSIONS.rekey_time_seconds via
        // numeric_min_better — an observed value higher than this
        // (less frequent rotation) is a deviation. 14400s (4h) is the
        // strongSwan default, actually observed in the lab.
        options: ["3600", "7200", "14400", "28800", "86400"],
        recommended: "14400"
      },
      {
        label: "Child SA rekey time (s)", key: "child_sa_rekey_time",
        // Compared by CHILD_SA_DIMENSIONS.lifetime_seconds. Realistic
        // values much lower than the IKE one: the data plane must be
        // rotated more often than the control channel.
        options: ["600", "1200", "1800", "3600"],
        recommended: "1800"
      }
    ],
    assets: [
      { name: "clientext", role: "Remote client (road warrior)", ip: "10.0.0.50", host: "clientext" },
      { name: "mainfw",    role: "VPN concentrator / Perimeter firewall", ip: "10.0.0.1", host: "mainfw" }
    ],
    demoFindings: [
      {
        type: "ok",
        icon: "ti-circle-check",
        title: "PSK authentication verified on all observed sessions",
        desc: "ssl.log/ike on mainfw records no negotiation attempts with methods other than PSK for the sampled clientext endpoints."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "Session from the 'employee' pool attempting to reach the mgmt zone",
        desc: "conn.log detects a flow from an employee-pool IP towards the bastion host. The IP-based ACL on the firewall should block this traffic: check the rule for the employee pool."
      }
    ],
    selected: {
      ike_version: "IKEv2",
      auth_method: "X.509 certificates — ECDSA (recommended)",
      enc1: "AES_GCM_16-256",
      int1: "HMAC_SHA2_384",
      dh1: "ECP_384",
      enc2: "AES_GCM_16-256",
      pfs: "ECP_384 (group dedicated to rekey)",
      ike_rekey_time: "14400",
      child_sa_rekey_time: "1800"
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // For the administrator profile, the road-warrior tunnel may carry
    // access to the management network: high criticality and sensitivity
    // even though a single remote session lives shorter than an S2S tunnel.
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "365"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "critical"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "high"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "365",
      data_sensitivity: "critical",
      criticality: "high",
    }
  },

  {
    id: "vpn_site_to_site",
    navIcon: "ti-lock",
    protoFamily: "ipsec",
    name: "Site-to-Site VPN",
    proto: "IPsec / IKEv2 — StrongSwan",
    params: [
      {
        label: "IKE version", key: "ike_version",
        options: ["IKEv2", "IKEv1 (deprecated)"],
        recommended: "IKEv2"
      },
      {
        label: "IKE_AUTH authentication method", key: "auth_method",
        // For a permanent site-to-site link the recommended choice is
        // X.509 certificate authentication (not PSK): each gateway has an
        // individual cryptographic identity verifiable through a CA.
        // PSK is selectable to explicitly declare a suboptimal choice —
        // otherwise the dimension could never be violated.
        // PQ options (FALCON, DILITHIUM) are experimental on strongSwan
        // but can be modeled as Expected for future migration scenarios.
        options: [
          "X.509 certificates — ECDSA (recommended)",
          "X.509 certificates — RSA-2048 (⚠ vulnerable to Shor)",
          "PSK (Pre-Shared Key) (⚠ not recommended for permanent links)",
          "FALCON-512 (native PQ — experimental)",
          "CRYSTALS-Dilithium (native PQ — experimental)",
        ],
        recommended: "X.509 certificates — ECDSA (recommended)"
      },
      {
        label: "Phase 1 encryption (IKE)", key: "enc1",
        options: ["AES_GCM_16-256", "AES_GCM_16-128", "AES_CBC-256 (⚠ non-AEAD)", "3DES-CBC (broken)"],
        recommended: "AES_GCM_16-256"
      },
      {
        label: "Phase 1 PRF (integrity)", key: "int1",
        options: ["HMAC_SHA2_384", "HMAC_SHA2_256", "HMAC_SHA1 (⚠)", "HMAC_MD5 (broken)"],
        recommended: "HMAC_SHA2_384"
      },
      {
        label: "Phase 1 key exchange (IKE)", key: "dh1",
        options: ["ECP_384", "ECP_256", "ECP_521", "MODP_4096", "MODP_2048", "MODP_1024 (⚠)"],
        recommended: "ECP_384"
      },
      {
        label: "ESP encryption (data plane)", key: "enc2",
        options: ["AES_GCM_16-256", "AES_GCM_16-128", "AES_CBC-256 (⚠ non-AEAD)"],
        recommended: "AES_GCM_16-256"
      },
      {
        label: "PFS (phase 2 / rekey)", key: "pfs",
        options: ["ECP_256 (group dedicated to rekey)", "ECP_384 (group dedicated to rekey)", "Disabled — no group in ESP proposal (⚠)"],
        recommended: "ECP_256 (group dedicated to rekey)"
      },
      {
        label: "IKE SA rekey time (s)", key: "ike_rekey_time",
        options: ["3600", "7200", "14400", "28800", "86400"],
        recommended: "14400"
      },
      {
        label: "Child SA rekey time (s)", key: "child_sa_rekey_time",
        // A permanent site-to-site link can afford a slightly less
        // frequent data-plane rekey than a transient road-warrior
        // profile — 1200s (20 min) actually observed.
        options: ["600", "1200", "1800", "3600"],
        recommended: "1200"
      }
    ],
    assets: [
      { name: "vpnlocal",  role: "Local VPN endpoint",  ip: "10.5.0.1", host: "vpnlocal" },
      { name: "vpnremote", role: "Remote VPN endpoint", ip: "10.5.0.2", host: "vpnremote" }
    ],
    demoFindings: [
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "DH Group: MODP-2048 accepted as fallback",
        desc: "StrongSwan accepts MODP-2048 if the peer does not support elliptic curves. Observed in ssl.log on vpnremote. Remove the fallback from the IKE proposal."
      },
      {
        type: "ok",
        icon: "ti-circle-check",
        title: "PFS correctly enabled on both endpoints",
        desc: "Zeek observed the phase 2 DH renegotiation on all sampled sessions. Perfect Forward Secrecy active."
      }
    ],
    selected: {
      ike_version: "IKEv2",
      auth_method: "X.509 certificates — ECDSA (recommended)",
      enc1: "AES_GCM_16-256",
      int1: "HMAC_SHA2_384",
      dh1: "ECP_384",
      enc2: "AES_GCM_16-256",
      pfs: "ECP_256 (group dedicated to rekey)",
      ike_rekey_time: "14400",
      child_sa_rekey_time: "1200"
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // A site-to-site tunnel typically protects long-lived secrets
    // (topology, routes, pre-shared keys): high shelf time.
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "1825"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "confidential"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "high"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "1825",
      data_sensitivity: "confidential",
      criticality: "high",
    }
  },

  {
    id: "admin_ssh",
    navIcon: "ti-terminal-2",
    protoFamily: "ssh",
    name: "SSH Bastion Access",
    proto: "SSH #1 — clientext ↔ Bastion",

    // ── ProxyJump scenario ──────────────────────────────────────────────────
    // ClientExt does not establish one SSH session with AppServer through
    // the Bastion: it establishes TWO independent, overlapping SSH sessions.
    //
    //   NETWORK (TCP):
    //   ClientExt ──TCP──> Bastion ──TCP fwd──> AppServer
    //
    //   CRYPTOGRAPHY (SSH):
    //   ClientExt ═══ SSH #1 ═══> Bastion           (own authn + KEX)
    //   ClientExt ═══ SSH #2 ═══> AppServer          (own authn + KEX)
    //
    // The Bastion acts as a TCP forwarder for SSH session #2: it relays
    // opaque bytes between ClientExt and AppServer — it has no access to
    // the SSH #2 payload, neither decrypts nor renegotiates it.
    // KEX and authentication of SSH #2 happen end-to-end between
    // ClientExt and AppServer, even though the bytes physically transit
    // through the Bastion. The two cryptographic contexts are independent
    // and separately configurable in this GUI.

    isBastionProxyJump: true,   // flag for renderSessionDiagram / renderParams

    // ── SSH cryptographic context #1: ClientExt ↔ Bastion ───────────────────
    params: [
      {
        label: "Protocol version", key: "ssh_ver",
        options: ["SSHv2", "SSHv1 (broken)"],
        recommended: "SSHv2"
      },
      {
        label: "Key exchange", key: "kex",
        options: ["curve25519-sha256", "ecdh-sha2-nistp384", "mlkem768x25519-sha256 (hybrid PQ)", "mlkem1024x25519-sha256 (hybrid PQ)", "sntrup761x25519-sha512 (hybrid PQ)", "ecdh-sha2-nistp521+mlkem1024 (hybrid PQ)", "diffie-hellman-group14-sha256", "diffie-hellman-group1 (weak)"],
        recommended: "curve25519-sha256"
      },
      {
        label: "Session encryption", key: "enc",
        options: ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "3des-cbc (weak)"],
        recommended: "aes256-gcm@openssh.com"
      },
      {
        label: "Server-side authentication", key: "host_auth",
        options: ["ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ssh-rsa (⚠ key size not verifiable from here)", "ssh-xmss (native PQ — experimental OpenSSH)", "ssh-falcon-512 (native PQ — experimental)"],
        recommended: "ssh-ed25519"
      },
      {
        label: "User authentication", key: "user_auth",
        options: ["Public key", "FIDO2/WebAuthn", "Password (⚠)"],
        recommended: "Public key"
      },
      {
        label: "MAC algorithm", key: "mac",
        options: ["hmac-sha2-256-etm", "hmac-sha2-512-etm", "hmac-sha1 (weak)"],
        recommended: "hmac-sha2-256-etm"
      }
    ],
    selected: {
      ssh_ver: "SSHv2",
      kex: "curve25519-sha256",
      enc: "aes256-gcm@openssh.com",
      host_auth: "ssh-ed25519",
      user_auth: "Public key",
      mac: "hmac-sha2-256-etm"
    },

    // ── SSH cryptographic context #2: ClientExt ↔ AppServer ─────────────────
    // Configurable independently of SSH #1: AppServer may require a
    // different KEX or host authentication than Bastion. It inherits
    // nothing from the first context — every field must be declared explicitly.
    params2: [
      {
        label: "Protocol version", key: "ssh_ver2",
        options: ["SSHv2", "SSHv1 (broken)"],
        recommended: "SSHv2"
      },
      {
        label: "Key exchange", key: "kex2",
        options: ["curve25519-sha256", "ecdh-sha2-nistp384", "mlkem768x25519-sha256 (hybrid PQ)", "mlkem1024x25519-sha256 (hybrid PQ)", "sntrup761x25519-sha512 (hybrid PQ)", "ecdh-sha2-nistp521+mlkem1024 (hybrid PQ)", "diffie-hellman-group14-sha256", "diffie-hellman-group1 (weak)"],
        recommended: "curve25519-sha256"
      },
      {
        label: "Session encryption", key: "enc2",
        options: ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "3des-cbc (weak)"],
        recommended: "aes256-gcm@openssh.com"
      },
      {
        label: "Host authentication", key: "host_auth2",
        options: ["ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ssh-rsa (⚠ key size not verifiable from here)", "ssh-xmss (native PQ — experimental OpenSSH)", "ssh-falcon-512 (native PQ — experimental)"],
        recommended: "ssh-ed25519"
      },
      {
        label: "User authentication", key: "user_auth2",
        options: ["Public key", "FIDO2/WebAuthn", "Password (⚠)"],
        recommended: "Public key"
      },
      {
        label: "MAC algorithm", key: "mac2",
        options: ["hmac-sha2-256-etm", "hmac-sha2-512-etm", "hmac-sha1 (weak)"],
        recommended: "hmac-sha2-256-etm"
      }
    ],
    selected2: {
      ssh_ver2: "SSHv2",
      kex2: "curve25519-sha256",
      enc2: "aes256-gcm@openssh.com",
      host_auth2: "ssh-ed25519",
      user_auth2: "Public key",
      mac2: "hmac-sha2-256-etm"
    },

    // ── Assets: the three nodes of the ProxyJump chain ──────────────────────
    // clientext → bastion → appserver
    // internalgw removed: it is not involved in the SSH Bastion Access use case.
    assets: [
      { name: "clientext", role: "Remote SSH client (initiator)", ip: "10.0.0.50", host: "clientext" },
      { name: "bastion",   role: "Bastion host — TCP forwarder / jump server", ip: "10.3.0.2",  host: "bastion"   },
      { name: "appserver", role: "Final target of SSH session #2",             ip: "10.2.0.10", host: "appserver" }
    ],

    demoFindings: [
      {
        type: "fail",
        icon: "ti-x",
        title: "Password authentication enabled on bastion (SSH #1)",
        desc: "ssh.log reveals password-authenticated sessions (auth_method: password) towards bastion. Disable PasswordAuthentication in sshd_config and enforce public keys."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "RSA-2048 in appserver host keys (SSH #2)",
        desc: "Present in known_hosts as a fallback algorithm for legacy clients. Remove it and enforce Ed25519 or ECDSA-384 exclusively."
      },
      {
        type: "ok",
        icon: "ti-circle-check",
        title: "curve25519-sha256 as primary KEX — both contexts",
        desc: "Zeek ssh.log records curve25519-sha256 as the key exchange algorithm for all sessions towards bastion and appserver. Compliant with the policy."
      }
    ],

    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "365"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "critical"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "high"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "365",
      data_sensitivity: "critical",
      criticality: "high",
    }
  },

  {
    id: "api_gateway_tls13",
    navIcon: "ti-api",
    protoFamily: "tls",
    name: "API Gateway TLS",
    proto: "TLS — public API, server-side authentication only",
    // The name and description no longer pin a version: apigw supports
    // both TLS 1.2 and TLS 1.3 (the "TLS version" parameter below picks
    // which), and showing "TLS 1.3" in the name even when the operator
    // configures TLS 1.2 would be misleading — the badge must reflect the
    // chosen configuration, not a fixed assumption.
    params: [
      {
        label: "TLS version", key: "tls_ver",
        options: ["TLS 1.3 only", "TLS 1.3 + 1.2", "TLS 1.2 only (⚠)"],
        recommended: "TLS 1.3 only"
      },
      {
        label: "Cipher suite", key: "cipher",
        // Depends on the TLS version selected above: TLS 1.2 and 1.3
        // share neither naming nor construction of their cipher suites.
        // Changing "TLS version" recomputes these options and, if the
        // already-selected cipher is no longer valid in the new context,
        // realigns it automatically (see updateParam in app.js).
        options: tlsCipherOptionsFor,
        recommended: tlsCipherRecommendedFor
      },
      {
        label: "Perfect Forward Secrecy", key: "pfs",
        // Observable for TLS 1.3 as well (Zeek's has_pfs field does not
        // depend on certificate visibility) — unlike "Server certificate",
        // removed: this one stays comparable always, regardless of the
        // negotiated version.
        options: ["Required", "Not required (⚠)"],
        recommended: "Required"
      },
      // "Client authentication" parameter (Bearer token / X.509 certificate
      // / mTLS / None) REMOVED: it mixed a mechanism native to the TLS
      // protocol (mTLS — the only one Zeek can actually observe, via
      // client_cert_chain_fps in cbom_loader.py) with an application-level
      // mechanism (Bearer token, verified by the HTTP server inside the
      // encrypted payload, structurally invisible to a TLS capture).
      // "Bearer token" was moreover the default recommended value: a
      // policy the comparison engine could never validate, staying
      // NOT_COMPARABLE regardless of what actually happened on the
      // connection — contrary to the system's principle of never declaring
      // comparable what is not.
      {
        label: "ECDH curve", key: "curve",
        // Depends on the mechanism implied by the selected cipher suite
        // (see tlsCurveOptionsFor at the top of the file): for an ECDHE_*
        // suite or any TLS 1.3 suite, the group/curve remains a truly
        // independent, selectable parameter; for a static RSA or
        // finite-field DHE suite, the field collapses to a single explicit
        // "Not applicable" option, because in those cases the protocol
        // negotiates no elliptic curve.
        // X25519MLKEM768 is the hybrid TLS 1.3 group being standardized by
        // the IETF (draft-ietf-tls-ecdhe-mlkem, IESG-approved), already
        // used by Chrome/Firefox/Cloudflare/AWS — not a theoretical option.
        // Classified SAFE_PQ by kex_level(), not equivalent to plain
        // x25519: a hybrid is worth more.
        options: tlsCurveOptionsFor,
        recommended: tlsCurveRecommendedFor
      },
      {
        label: "Server certificate (algorithm)", key: "cert",
        // Not "does the certificate exist?" — its presence is an invariant
        // of authenticated TLS (guaranteed by construction, except for
        // anonymous cipher suites, now extinct), not something to verify.
        // What actually varies, and makes sense to configure, is the
        // certificate's ALGORITHM/key length.
        // Visibility depends on the selected TLS version (see
        // tlsCertOptionsFor at the top of the file): with "TLS 1.3 only"
        // the field becomes non-configurable — the Certificate message is
        // encrypted by construction (RFC 8446), not because of a pipeline
        // limitation — while with "TLS 1.2 only" or "TLS 1.3 + 1.2" it
        // stays fully selectable (in the latter case, a legacy client
        // negotiating 1.2 still makes the field observable for those
        // sessions — which actually happened for apigw, see demoFindings).
        // When not observable in the sampled session, the reason still
        // appears explicitly in the Comparison tab
        // (host_key_unavailable_reason, taken from this session's real
        // JSON, never assumed in the abstract for the use case).
        options: tlsCertOptionsFor,
        recommended: tlsCertRecommendedFor
      },
      {
        label: "OCSP Stapling", key: "ocsp",
        // Deliberately never mapped in EXPECTED_FIELD_MAP: Zeek does not
        // observe the OCSP stapling extension in the TLS handshake — it
        // remains a policy declaration, not tied to any automatic
        // comparison. Not an omission: a data source that doesn't allow it.
        options: ["Enabled", "Disabled (⚠)"],
        recommended: "Enabled"
      }
    ],
    assets: [
      // clientext is the TLS initiator: it uses a virtual IP assigned from
      // the VPN pool, not statically configurable — it depends on the active
      // road-warrior profile. Not editable in the GUI: the real IP is
      // resolved from the Zeek inventory.
      { name: "clientext", role: "Remote TLS client (road warrior)", ip: "10.9.2.1", host: "clientext",
        readonly: true, note: "VPN pool virtual IP — not editable" },
      // apigw is the TLS terminator: fixed IP, editable in the GUI.
      { name: "apigw", role: "DMZ API Gateway — TLS terminator", ip: "10.1.0.10", host: "apigw" },
    ],
    demoFindings: [
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "TLS 1.2 negotiated by legacy clients towards apigw",
        desc: "ssl.log records 3 TLS 1.2 sessions in the last 10 minutes. The policy requires TLS 1.3 exclusively. Identify the non-compliant clients."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "No client application-level authentication observed",
        desc: "x509.log confirms that apigw neither requests nor verifies any client certificate — consistent with the actual nginx configuration (no ssl_verify_client directive). This use case does not declare mTLS as a requirement: if the API still relies on application-level authentication (token, API key), that check lives entirely above the TLS layer and is not a dimension tracked by this assessment."
      }
    ],
    selected: {
      tls_ver: "TLS 1.3 only",
      cipher: "TLS_AES_256_GCM_SHA384",
      pfs: "Required",
      curve: "x25519",
      // Consistent with tlsCertOptionsFor: with the default tls_ver
      // "TLS 1.3 only" the field is not applicable, so the default must
      // reflect that — not an arbitrary algorithm. showUseCase renders the
      // initial state directly, without going through updateParam's
      // realignment cycle (which only fires when a parameter changes): an
      // inconsistent default here would remain invisible in the internal
      // state even with the select disabled in the UI, and would still end
      // up in the payload — exactly the kind of phantom value this
      // mechanism is meant to prevent.
      cert: "Not applicable — TLS 1.3 encrypts the Certificate message by construction (RFC 8446)",
      ocsp: "Enabled"
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // API traffic with certificates already on fast rotation (see
    // cert_rotation_hours in schema.py): short shelf time by design.
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "90"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "confidential"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "high"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "90",
      data_sensitivity: "confidential",
      criticality: "high",
    }
  },

  {
    id: "backup_sftp",
    navIcon: "ti-database",
    protoFamily: "ssh",
    name: "SFTP Backup",
    proto: "SFTP — OpenSSH (scheduled)",
    params: [
      {
        label: "Protocol version", key: "ssh_ver",
        // Added for parity with admin_ssh: SSH always exposes its version
        // in the handshake, regardless of the use case — unlike TLS 1.3,
        // there is no protocol limit to observability here. It was missing
        // not because of a real limitation, but because this use case's
        // form didn't ask for it yet.
        options: ["SSHv2", "SSHv1 (broken)"],
        recommended: "SSHv2"
      },
      {
        label: "Authentication", key: "auth",
        options: ["Public key", "Password (⚠)"],
        recommended: "Public key"
      },
      {
        label: "KEX", key: "kex",
        options: ["curve25519-sha256", "mlkem768x25519-sha256 (hybrid PQ)", "sntrup761x25519-sha512 (hybrid PQ)", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
        recommended: "curve25519-sha256"
      },
      {
        label: "Encryption", key: "enc",
        options: ["aes256-gcm@openssh.com", "aes256-ctr", "aes128-gcm@openssh.com"],
        recommended: "aes256-gcm@openssh.com"
      },
      {
        label: "Host authentication (algorithm)", key: "host_auth",
        // Added for parity with admin_ssh — same vocabulary, same known
        // limitation (an SSH host key identifier never carries the key
        // size in its name). Distinct from "Host key verification": that
        // is a policy on the client's BEHAVIOR when facing a new/unknown
        // key (StrictHostKeyChecking), not on the key's ALGORITHM — two
        // independent declarations, not redundant.
        options: ["ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ssh-rsa (⚠ key size not verifiable from here)", "ssh-xmss (native PQ — experimental OpenSSH)", "ssh-falcon-512 (native PQ — experimental)"],
        recommended: "ssh-ed25519"
      },
      // "Compression" removed: ssh_parser.py reads compression_alg but
      // cbom_loader does not map it onto ObservedCryptoProfile and
      // SSH_DIMENSIONS has no comparator for it. It is not a cryptographic
      // dimension (affects neither confidentiality nor integrity) — not comparable.
      //
      // "Host key verification" (StrictHostKeyChecking) removed: it is an
      // SSH client configuration policy, not a parameter negotiated in the
      // session. Zeek works passively on traffic — it has no access to the
      // client configuration and cannot observe this parameter.
      // It is not present in ObservedCryptoProfile nor in SSH_DIMENSIONS.
      {
        label: "MAC integrity", key: "mac",
        options: ["hmac-sha2-256-etm", "hmac-sha2-512-etm", "hmac-sha1 (weak)"],
        recommended: "hmac-sha2-256-etm"
      }
    ],
    assets: [
      { name: "backupsrv", role: "Backup server", ip: "10.2.0.11", host: "backupsrv" },
      { name: "appserver", role: "Backup source", ip: "10.2.0.10", host: "appserver" }
    ],
    demoFindings: [
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "StrictHostKeyChecking not enforced in the last session",
        desc: "The scheduled SFTP client (cron) accepted a new host key without manual confirmation. Possible unauthorized rotation of the server key."
      },
      {
        type: "ok",
        icon: "ti-circle-check",
        title: "Public key authentication confirmed",
        desc: "ssh.log records auth_method: publickey on all backup sessions. No static credentials exposed in the cron job."
      }
    ],
    selected: {
      ssh_ver: "SSHv2",
      auth: "Public key",
      kex: "curve25519-sha256",
      enc: "aes256-gcm@openssh.com",
      host_auth: "ssh-ed25519",
      // comp and host_verify removed — not comparable by the pipeline
      mac: "hmac-sha2-256-etm"
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // Backups typically have the longest retention period of all use
    // cases: ten-year shelf time, maximum sensitivity.
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "3650"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "critical"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "high"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "3650",
      data_sensitivity: "critical",
      criticality: "high",
    }
  },

  {
    id: "service_mesh",
    navIcon: "ti-topology-star",
    protoFamily: "tls",
    name: "Service Mesh",
    proto: "Internal TLS / mTLS — inter-service",
    params: [
      {
        label: "TLS version", key: "tls_ver",
        options: ["TLS 1.3 only", "TLS 1.3 + 1.2"],
        recommended: "TLS 1.3 only"
      },
      {
        label: "Identity certificate (key)", key: "identity",
        // No longer framework names (SPIFFE/SVID, static X.509) — those
        // are never classifiable by hostkey_level(), which evaluates
        // algorithm and key length, not the identity management framework.
        // Observable only if the session negotiates TLS ≤1.2 (for TLS 1.3,
        // always the case in the lab today, the certificate is
        // structurally encrypted — the reason appears automatically in the
        // Comparison tab when it applies, it is not an assumption fixed here).
        options: ["ecdsa-384", "ecdsa-256", "rsa-4096", "rsa-2048 (⚠)"],
        recommended: "ecdsa-384"
      },
      {
        label: "Cert. rotation (hours)", key: "rotation",
        // Honest note: the current comparison engine evaluates the latest
        // observed sample, not a historical series — rotation cadence over
        // time is not yet an automatically verifiable dimension with this
        // data model. It stays here as a policy declaration, useful for
        // human review and for the Cypher output, not tied to an automatic
        // comparison until a time-series model exists.
        options: ["Automatic (< 24h)", "Manual (⚠)", "None (⚠)"],
        recommended: "Automatic (< 24h)"
      },
      {
        label: "Cipher suite", key: "cipher",
        // Before this update: a static list of just 2 TLS 1.3-style
        // suites, never reflecting the selected TLS version — choosing
        // "TLS 1.3 + 1.2" the operator still could not declare a
        // TLS 1.2-format suite. Now shared with all other TLS use cases
        // through the same lists and version-gating functions.
        options: tlsCipherOptionsFor,
        recommended: tlsCipherRecommendedFor
      },
      {
        label: "ECDH curve", key: "curve",
        // It was missing entirely: Expected.kex was never populated by any
        // parameter for this use case, so the "kex" dimension of
        // TLS_DIMENSIONS was always "Not comparable" — not because of a
        // protocol limit (unlike the host key below, structurally
        // encrypted in TLS 1.3), but because the field had never been
        // added to the GUI: the group/curve travels in the key_share
        // extension, observable even when the session negotiates TLS 1.3.
        // Same treatment already used for api_gateway_tls13 and
        // syslog_tls: depends on the mechanism implied by the cipher suite
        // selected above (tlsCurveOptionsFor at the top of the file) — now
        // that "cipher" shares TLS12_CIPHER_OPTIONS with the other TLS use
        // cases, service_mesh too can select a static RSA or finite-field
        // DHE suite, so the field must be able to collapse to "Not
        // applicable" in the same way. It must appear AFTER "cipher" in the
        // array (not before): the realignment cascade in updateParam
        // evaluates parameters in declaration order, and curve must see
        // cipher's already-updated value in the same pass, not the previous one.
        options: tlsCurveOptionsFor,
        recommended: tlsCurveRecommendedFor
      },
      {
        label: "Perfect Forward Secrecy", key: "pfs",
        // Added for parity with api_gateway_tls13 — it was missing
        // entirely, despite being observable for TLS regardless of the
        // negotiated version (Zeek's has_pfs does not depend on certificate
        // visibility, unlike the host key below). buildExpectedPayload
        // already maps it to has_pfs for ANY use case with protoFamily
        // "tls" — no change to app.js needed to activate it here.
        options: ["Required", "Not required (⚠)"],
        recommended: "Required"
      },
      {
        label: "mTLS policy", key: "mtls_policy",
        // STRICT implies mTLS always enforced: now derived in
        // buildExpectedPayload into mutual_auth/client_cert_required, the
        // same treatment already given to "client_auth" elsewhere — the
        // most relevant security property for a zero-trust service mesh
        // ("is mTLS really enforced?") finally becomes verifiable against
        // observation, not just declared.
        // PERMISSIVE/DISABLE do not produce a clear-cut expectation to
        // compare (PERMISSIVE explicitly accepts both cases; DISABLE denies
        // mTLS, but an expectation "mutual_auth must be false" is not a
        // pattern cmp_boolean_implication evaluates in this system — see
        // note on pfs_capable).
        options: ["STRICT", "PERMISSIVE (⚠)", "DISABLE (⚠)"],
        recommended: "STRICT"
      }
    ],
    assets: [
      { name: "svca", role: "Microservice A", ip: "10.4.0.10", host: "svca" },
      { name: "svcb", role: "Microservice B", ip: "10.4.0.11", host: "svcb" }
    ],
    demoFindings: [
      {
        type: "ok",
        icon: "ti-circle-check",
        title: "mTLS enforced on all observed sessions",
        desc: "ssl.log on netmesh records no unencrypted connections — every svca ↔ svcb session negotiates TLS 1.3."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "128-bit cipher suite, not 256",
        desc: "ssl.log confirms TLS_AES_128_GCM_SHA256 on all observed sessions — gRPC declares no explicit cipher suite preference, unlike apigw. The policy recommends 256 bits."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "Certificate identity not automatically verifiable",
        desc: "TLS 1.3 encrypts the Certificate message by protocol construction — x509.log never carries an entry for these sessions, regardless of which certificate is actually in use. Verifying the algorithm/key length requires an out-of-band check (e.g. reading the certificate file directly from the filesystem)."
      }
    ],
    selected: {
      tls_ver: "TLS 1.3 only",
      identity: "ecdsa-384",
      rotation: "Automatic (< 24h)",
      cipher: "TLS_AES_256_GCM_SHA384",
      curve: "x25519",
      pfs: "Required",
      mtls_policy: "STRICT"
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // Internal inter-service traffic, already covered by < 24h rotation
    // (the "rotation" cryptographic parameter above, mapped to
    // cert_rotation_hours in the Expected node).
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "90"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "confidential"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "medium"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "90",
      data_sensitivity: "confidential",
      criticality: "medium",
    }
  },

  {
    id: "mail_tls",
    navIcon: "ti-mail",
    protoFamily: "tls",
    name: "Mail TLS",
    proto: "SMTP over TLS — STARTTLS",
    params: [
      {
        label: "TLS mode", key: "mode",
        options: ["STARTTLS mandatory", "STARTTLS optional (⚠)", "Implicit (port 465)", "None (⚠)"],
        recommended: "STARTTLS mandatory"
      },
      {
        label: "TLS version", key: "tls_ver",
        options: ["TLS 1.3 + 1.2", "TLS 1.2 only", "TLS 1.1 (broken)"],
        recommended: "TLS 1.3 + 1.2"
      },
      {
        label: "Certificate", key: "cert",
        // Combined type-length format, consistent with cbom_loader.py.
        // Note for the operator: mailsrv in the lab DELIBERATELY uses
        // RSA-2048 (the only exception to the ECDSA policy adopted
        // elsewhere), to give the assessment a real deviation case to
        // judge — don't fix it in the lab, it's intentional; the policy
        // below still reflects what one would expect from a well-maintained
        // service, not the current state.
        options: ["ecdsa-384", "ecdsa-256", "rsa-2048 (⚠ observed on mailsrv)", "rsa-4096"],
        recommended: "ecdsa-384"
      },
      {
        label: "DANE/TLSA", key: "dane",
        options: ["Enabled", "Disabled (⚠)"],
        recommended: "Enabled"
      },
      {
        label: "MTA-STS", key: "mta_sts",
        options: ["Enforce policy", "Testing policy", "None (⚠)"],
        recommended: "Enforce policy"
      },
      {
        label: "Cipher suite", key: "cipher12",
        // Key "cipher12" kept unchanged (no visibility here into the
        // backend EXPECTED_FIELD_MAP mapping, so as not to risk
        // misaligning the payload sent to /api/usecases).
        // Before this update: a static list of TLS 1.2 suites only, never
        // exposed in TLS 1.3 format, despite "TLS 1.3 + 1.2" being the
        // default option for "TLS version" above — an operator who had
        // actually negotiated TLS 1.3 could not declare it correctly in
        // this field. Now shared with the other TLS use cases through the
        // same lists/gating functions, including the "TLS 1.1 (broken)"
        // fallback → TLS 1.2 naming (same IANA namespace, see tls12Only).
        options: tlsCipherOptionsFor,
        recommended: tlsCipherRecommendedFor
      },
      {
        label: "ECDH curve", key: "curve",
        // Same gap already found and fixed in service_mesh: Expected.kex
        // was never populated for this use case, so the "kex" dimension
        // was always "Not comparable" — not because of a protocol limit,
        // only because the field had never been added.
        // tlsKeyExchangeMechanism (at the top of the file) already reads
        // "sel.cipher || sel.cipher12", so tlsCurveOptionsFor works here
        // without any change: with the "cipher12" key set to a static RSA
        // or finite-field DHE suite, the field automatically collapses to
        // "Not applicable", exactly as for the other TLS use cases. It must
        // appear AFTER "cipher12" in the array for the same cascade-order
        // reason noted elsewhere.
        options: tlsCurveOptionsFor,
        recommended: tlsCurveRecommendedFor
      }
    ],
    assets: [
      { name: "mailsrv",   role: "DMZ mail server",     ip: "10.1.0.11", host: "mailsrv" },
      { name: "appserver", role: "SMTP sending origin", ip: "10.2.0.10", host: "appserver" }
    ],
    demoFindings: [
      {
        type: "fail",
        icon: "ti-x",
        title: "DANE not configured — downgrade possible",
        desc: "Zeek conn.log records SMTP connections towards remote MTAs without TLSA validation. A MitM attacker can force plaintext connections."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "MTA-STS in testing mode — violations not blocked",
        desc: "MTA-STS policy violations are reported but not enforced. Switch to enforce mode after validating the report."
      },
      {
        type: "ok",
        icon: "ti-circle-check",
        title: "STARTTLS mandatory — no plaintext traffic",
        desc: "ssl.log confirms TLS negotiated on all SMTP sessions observed on mailsrv. No plaintext sessions detected."
      }
    ],
    selected: {
      mode: "STARTTLS mandatory",
      tls_ver: "TLS 1.3 + 1.2",
      cert: "ecdsa-384",
      dane: "Enabled",
      mta_sts: "Enforce policy",
      cipher12: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      curve: "secp384r1"
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // Mail archived for compliance/audit purposes: multi-year shelf time,
    // sensitivity only "internal" by default (raise to "confidential"/
    // "critical" if the mailbox handles personal data or trade secrets).
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "730"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "internal"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "medium"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "730",
      data_sensitivity: "internal",
      criticality: "medium",
    }
  },
  {
    id: "sftp_dmz",
    navIcon: "ti-folder-share",
    protoFamily: "ssh",
    name: "SFTP DMZ",
    proto: "SFTP — SSH subsystem (road-warrior access to DMZ)",
    params: [
      {
        label: "Protocol version", key: "ssh_ver",
        // Added for parity with admin_ssh — see identical note on
        // backup_sftp: no real limit to observability for SSH, it was
        // missing only because the form didn't ask for it.
        options: ["SSHv2", "SSHv1 (broken)"],
        recommended: "SSHv2"
      },
      {
        label: "User authentication", key: "auth",
        options: ["Public key", "FIDO2/WebAuthn", "Password (⚠)"],
        recommended: "Public key"
      },
      {
        label: "Key exchange", key: "kex",
        options: ["curve25519-sha256", "ecdh-sha2-nistp384", "mlkem768x25519-sha256 (hybrid PQ)", "mlkem1024x25519-sha256 (hybrid PQ)", "sntrup761x25519-sha512 (hybrid PQ)", "ecdh-sha2-nistp521+mlkem1024 (hybrid PQ)", "diffie-hellman-group14-sha256", "diffie-hellman-group1 (weak)"],
        recommended: "curve25519-sha256"
      },
      {
        label: "Session encryption", key: "enc",
        options: ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr", "3des-cbc (weak)"],
        recommended: "chacha20-poly1305@openssh.com"
      },
      {
        label: "Host authentication (algorithm)", key: "host_auth",
        // Added for parity with admin_ssh — see identical note on
        // backup_sftp. Distinct from "Filesystem confinement" (chroot):
        // that concerns what the server lets the authenticated client see,
        // not the server's cryptographic identity.
        options: ["ssh-ed25519", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "ssh-rsa (⚠ key size not verifiable from here)", "ssh-xmss (native PQ — experimental OpenSSH)", "ssh-falcon-512 (native PQ — experimental)"],
        recommended: "ssh-ed25519"
      },
      {
        label: "MAC algorithm", key: "mac",
        options: ["hmac-sha2-256-etm", "hmac-sha2-512-etm", "hmac-sha1 (weak)"],
        recommended: "hmac-sha2-256-etm"
      },
      // "Filesystem confinement" removed: ChrootDirectory is an sshd
      // directive, not a parameter negotiated in the handshake. Not
      // observable by Zeek, not in ObservedCryptoProfile, not in SSH_DIMENSIONS.
    ],
    assets: [
      { name: "ftpsrv",    role: "DMZ SFTP server",              ip: "10.1.0.12", host: "ftpsrv" },
      { name: "clientext", role: "Remote client (road warrior)", ip: "10.0.0.50", host: "clientext" }
    ],
    demoFindings: [
      {
        type: "ok",
        icon: "ti-circle-check",
        title: "Chroot confinement confirmed",
        desc: "sshd_config on ftpsrv applies ChrootDirectory + ForceCommand internal-sftp with AllowTcpForwarding no. No escape route to a login shell or a generic tunnel."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "Same protocol and port as SFTP Backup — attribution via hostname only",
        desc: "SFTP towards ftpsrv and towards backupsrv are indistinguishable from observed traffic alone (same port 22). Correct attribution depends entirely on the asset inventory declared in this GUI, not on data observable on the wire."
      }
    ],
    selected: {
      ssh_ver: "SSHv2",
      auth: "Public key",
      kex: "curve25519-sha256",
      enc: "chacha20-poly1305@openssh.com",
      host_auth: "ssh-ed25519",
      mac: "hmac-sha2-256-etm",
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // Files transferred from an external client via road-warrior: higher
    // sensitivity than a purely internal transfer such as SFTP Backup.
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "90"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "confidential"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "medium"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "90",
      data_sensitivity: "confidential",
      criticality: "medium",
    }
  },
  {
    id: "syslog_tls",
    navIcon: "ti-file-text",
    protoFamily: "tls",
    name: "Syslog TLS",
    proto: "syslog over TLS — RFC 5425, server-side authentication only",
    // Unlike every other TLS use case in the lab: here client
    // authentication is not an option to enable, it is structurally absent
    // in the observed configuration (StreamDriver.Authmode="anon" on the
    // rsyslog side). "None" is the REAL value, not an insecure fallback to
    // flag as an isolated anomaly — the policy itself must explicitly
    // acknowledge it.
    params: [
      {
        label: "TLS version", key: "tls_ver",
        options: ["TLS 1.3 only", "TLS 1.2 (observed)", "TLS 1.1 or lower (⚠)"],
        recommended: "TLS 1.3 only"
      },
      {
        label: "Cipher suite", key: "cipher",
        // Before this update: a static list of 3 entries mixing TLS 1.2
        // naming (TLS_ECDHE_ECDSA_WITH_...), TLS 1.3
        // (TLS_AES_256_GCM_SHA384) and a static RSA suite, all offered
        // together regardless of "TLS version" above — the same defect
        // already fixed earlier for api_gateway_tls13, not yet applied
        // here. Now shared with all other TLS use cases through
        // tlsCipherOptionsFor/tlsCipherRecommendedFor.
        options: tlsCipherOptionsFor,
        recommended: tlsCipherRecommendedFor
      },
      {
        label: "Key exchange (curve)", key: "curve",
        // Not redundant with the cipher suite in general (see note on
        // tlsCurveOptionsFor at the top of the file) — it only becomes so
        // when the selected suite is static RSA key transport, with no
        // Diffie-Hellman negotiation at all: in that case the field
        // automatically collapses to a single "Not applicable" option,
        // instead of continuing to offer curves the protocol can never
        // negotiate with that suite. With an ECDHE_* suite (the case
        // actually observed in the lab: TLS 1.2 with
        // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) the parameter stays
        // fully selectable — before an earlier revision it was entirely
        // absent for this use case, and Expected.kex was always "Not
        // comparable" regardless of what was actually observed.
        options: tlsCurveOptionsFor,
        recommended: tlsCurveRecommendedFor
      },
      {
        label: "Server authentication (key)", key: "server_auth",
        // Fixed: these used to be policy concepts ("Certificate verified
        // (internal CA)"), never algorithm names — hostkey_level() cannot
        // classify them, and an unclassifiable value was treated as "0.5"
        // instead of "not comparable": a real bug (fixed in
        // comparators.py), found precisely thanks to this use case.
        options: ["ecdsa-256", "ecdsa-384", "rsa-4096", "rsa-2048 (⚠)"],
        recommended: "ecdsa-384"
      },
      {
        label: "Client authentication", key: "client_auth",
        // Honest note, not a placeholder: Zeek only observes WHETHER a
        // client certificate was presented (mTLS confirmed), never its
        // absence reliably — a client authenticated with a method invisible
        // at the TLS layer (which doesn't exist here, but may in other use
        // cases) would be indistinguishable from no authentication. That's
        // why the absence of a certificate is NEVER inferred as "None": it
        // stays not comparable rather than risking a false deviation.
        options: ["Client certificate (mTLS)", "None"],
        recommended: "Client certificate (mTLS)"
      }
    ],
    assets: [
      { name: "logserver", role: "Centralized log collection", ip: "10.2.0.12", host: "logserver" },
      { name: "appserver", role: "Only configured client",     ip: "10.2.0.10", host: "appserver" }
    ],
    demoFindings: [
      {
        type: "fail",
        icon: "ti-x",
        title: "No sender authentication — StreamDriver.Authmode=\"anon\"",
        desc: "The channel is encrypted and the server is authenticated, but logserver neither requests nor verifies any client certificate. The %HOSTNAME% field is declared by the sender, not a cryptographic identity: any host with connectivity to port 6514 could claim to be another host."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "TLS 1.2 negotiated, not TLS 1.3",
        desc: "ssl.log confirms TLSv12 with cipher TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 on the observed session towards logserver — the policy recommends TLS 1.3, rsyslog's gtls driver negotiates 1.2 here."
      },
      {
        type: "warn",
        icon: "ti-alert-triangle",
        title: "Only one client configured out of several log-generating hosts",
        desc: "Only appserver forwards logs to logserver in the current state of the lab — partial centralization, not representative of an infrastructure where every relevant host should forward its logs."
      }
    ],
    selected: {
      tls_ver: "TLS 1.2 (observed)",
      cipher: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      curve: "secp256r1",
      server_auth: "ecdsa-384",
      client_auth: "None"
    },
    // ─── Lifecycle & Data Governance ───────────────────────────────
    // Logs may contain sensitive operational data and must be retained
    // longer than most application traffic — long shelf time by design,
    // not by oversight.
    governance: [
      {
        label: "Data shelf time (days)", key: "shelf_time_days",
        options: ["30", "90", "365", "1825", "3650"],
        recommended: "1825"
      },
      {
        label: "Sensitivity of transported data", key: "data_sensitivity",
        options: ["public", "internal", "confidential", "critical"],
        recommended: "internal"
      },
      {
        label: "Use-case criticality", key: "criticality",
        options: ["low", "medium", "high"],
        recommended: "medium"
      },
    ],
    selectedGovernance: {
      shelf_time_days: "1825",
      data_sensitivity: "internal",
      criticality: "medium",
    }
  }
];