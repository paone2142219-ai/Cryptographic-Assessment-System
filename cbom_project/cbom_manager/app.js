// =====================================================================
// CBOM Enrichment via Ontological Modeling — Sapienza University of Rome
// app.js — GUI application logic
//
// Four responsibilities:
//   1. Rendering the tabs (parameters, assets, findings, cypher) from
//      USE_CASES (data.js)
//   2. Mapping the GUI's "readable" parameters onto the snake_case
//      properties of the :Expected node (schema.py / graph_writer.py)
//   3. HTTP communication with the FastAPI backend (GUI ↔ graph boundary)
//   4. Lifecycle & Data Governance: shelf time, data sensitivity and
//      post-quantum posture, with a client-side preview of the EXPECTED
//      side of the "harvest-now-decrypt-later" exposure (mirror of
//      quantum_risk.assess in the backend; the observed side is computed
//      on ingest and read back from the graph)
// =====================================================================

const API_BASE = "http://localhost:8000";

let currentUC = 0;

// ─── GUI → ONTOLOGICAL SCHEMA MAPPING ───────────────────────────────────
// Each use case has parameters with different labels (e.g. "IKE version"
// for VPN, "Protocol version" for SSH), but they must all flow into the
// same :Expected node properties defined in the domain vocabulary:
// protocol_version, cipher, kex, host_key_algo, auth_method, mac,
// mutual_auth, client_cert_required, cert_rotation_hours.
//
// This table maps, for each use case, the GUI parameter key
// (uc.selected[key]) to the corresponding Expected property.
// It is the exact point where "the high-level behavior described by the
// operator" becomes "a concrete value on the Expected node".

const EXPECTED_FIELD_MAP = {
  vpn_road_warrior: {
    // No field mapped onto the generic profile: after the fix, the
    // generic profile is no longer evaluated for IPsec use cases
    // (it was always not_comparable anyway, never real information).
    // ike_version/auth_method/rekey time now live only in the IKE SA /
    // Child SA sub-profiles, via buildIpsecSubProfiles — one source, not two.
  },
  vpn_site_to_site: {
    // Same reason as vpn_road_warrior — see above.
  },
  admin_ssh: {
    ssh_ver: "protocol_version",
    kex: "kex",
    enc: "cipher",
    host_auth: "host_key_algo",
    user_auth: "auth_method",
    mac: "mac",
  },
  api_gateway_tls13: {
    tls_ver: "protocol_version",
    cipher: "cipher",
    curve: "kex",
    cert: "host_key_algo",
    // client_auth: "auth_method" removed — it mixed a native TLS
    // mechanism (mTLS) with an application-level one (Bearer token) never
    // observable by the Zeek pipeline. See note in data.js on the removed parameter.
  },
  backup_sftp: {
    // ssh_ver and host_auth added for parity with admin_ssh — see note
    // in data.js: no real limit to observability for SSH, they were
    // missing only because the form didn't ask for these two fields.
    ssh_ver: "protocol_version",
    auth: "auth_method",
    kex: "kex",
    enc: "cipher",
    host_auth: "host_key_algo",
    mac: "mac",
  },
  sftp_dmz: {
    ssh_ver: "protocol_version",
    auth: "auth_method",
    kex: "kex",
    enc: "cipher",
    host_auth: "host_key_algo",
    mac: "mac",
  },
  service_mesh: {
    tls_ver: "protocol_version",
    cipher: "cipher",
    curve: "kex",
    identity: "host_key_algo",
  },
  mail_tls: {
    tls_ver: "protocol_version",
    cipher12: "cipher",
    curve: "kex",
    cert: "host_key_algo",
  },
  syslog_tls: {
    tls_ver: "protocol_version",
    cipher: "cipher",
    curve: "kex",
    server_auth: "host_key_algo",
    client_auth: "auth_method",
  },
};

// Default zone and criticality for assets that don't specify them
// explicitly in data.js (refine this map as you extend the data with
// real values for each Kathará node).
const ASSET_DEFAULTS = {
  clientext:  { zone: "internet",      criticality: "medium" },
  vpnlocal:   { zone: "vpn_tunnel",    criticality: "high" },
  vpnremote:  { zone: "vpn_tunnel",    criticality: "high" },
  mainfw:     { zone: "dmz",           criticality: "high" },
  bastion:    { zone: "mgmt",          criticality: "high" },
  internalgw: { zone: "internal_lan",  criticality: "medium" },
  apigw:      { zone: "dmz",           criticality: "high" },
  dmzgw:      { zone: "dmz",           criticality: "medium" },
  backupsrv:  { zone: "internal_lan",  criticality: "medium" },
  appserver:  { zone: "internal_lan",  criticality: "medium" },
  svca:       { zone: "service_mesh",  criticality: "medium" },
  svcb:       { zone: "service_mesh",  criticality: "medium" },
  mailsrv:    { zone: "dmz",           criticality: "medium" },
  ftpsrv:     { zone: "dmz",           criticality: "medium" },
  logserver:  { zone: "internal_lan",  criticality: "medium" },
};

// Effective zone of an asset: an explicit value on the asset object itself
// (set e.g. when the operator adds a host from the GUI and picks its zone)
// always wins over the by-name default in ASSET_DEFAULTS — the same
// "only if absent" precedence used elsewhere in the file for defaults.
function zoneOf(asset) {
  return asset.zone || (ASSET_DEFAULTS[asset.name] && ASSET_DEFAULTS[asset.name].zone) || "internal_lan";
}

const ZONE_KEYS = ["internet", "dmz", "internal_lan", "mgmt", "service_mesh", "vpn_tunnel", "remote_site"];

// Prefix shared by all descriptive "Not applicable — ..." options in
// data.js (TLS_CURVE_NA_*, TLS_CERT_NA_TLS13): one constant, so that
// the check can't drift out of sync across the functions below.
const NOT_APPLICABLE_PREFIX = "Not applicable";
function isNotApplicable(val) {
  return typeof val === 'string' && val.startsWith(NOT_APPLICABLE_PREFIX);
}

// ─── LIFECYCLE & DATA GOVERNANCE ────────────────────────────────────────
// Unlike EXPECTED_FIELD_MAP, governance parameters
// (uc.governance / uc.selectedGovernance in data.js) already use keys
// identical to the Expected node properties (data_sensitivity): they were
// born "protocol-agnostic", so no dedicated
// semantic adapter is needed as for the cryptographic parameters.
// shelf_time_days and criticality are the exception: they are properties
// of the UseCase node, not of Expected, and are handled separately in
// buildUseCasePayload(). Criticality is now explicitly selected by the
// operator (it was previously derived automatically from data
// sensitivity: that implicit derivation has been removed).

// Client-side replica, for immediate preview in the GUI, of the EXPECTED
// side of the HNDL heuristic in quantum_risk.py (backend). The observed
// side (shelf time × worst key exchange over every observed session) can
// only be computed on ingest and is shown from the graph in the
// Expected/Observed comparison tab. Keep the threshold and the rule
// aligned by hand with quantum_risk.py.
const QUANTUM_RISK_SHELF_THRESHOLD_DAYS = 365;

// ─── PQC POSTURE DERIVATION — key exchange only, symmetric ─────────────────
// The post-quantum posture is a property of the KEY EXCHANGE alone: it
// answers "can traffic recorded today be decrypted once a quantum computer
// exists?" (harvest-now, decrypt-later), and only the way session keys are
// established decides that. PQ signatures (FALCON, ML-DSA, XMSS...) protect
// authentication at connection time, not the confidentiality of traffic
// already captured, so they do not change the posture. An earlier version
// derived it from EVERY selected value, so a FALCON signature on top of a
// classical KEX turned it "hybrid" and silenced the HNDL flag — a false
// negative, removed by construction here.
//
// Symmetry with the observed side:
//   - same function: kexPQPosture() below is a 1:1 mirror of
//     crypto_levels.kex_pq_posture() in the backend (same token lists, same
//     rules) — if you change one, change the other;
//   - same field: the expected kex of the use case (KEX_FIELD_BY_FAMILY),
//     i.e. exactly what the backend compares against the observed kex;
//   - authoritative value: computed by the BACKEND on save
//     (graph_writer._derive_expected_pq_postures), which overwrites
//     whatever this function sends — here it is only a live preview.
//
// Rules, on the bare algorithm name (GUI annotations such as "(hybrid PQ)"
// are stripped first: the posture is never read from a label):
//   PQ KEM token + classical token → hybrid (classical+PQ)
//   PQ KEM token only              → native PQ
//   no PQ KEM token (or no KEX)    → classical

const PQ_POSTURE = {
  NATIVE:    "native PQ",
  HYBRID:    "hybrid (classical+PQ)",
  CLASSICAL: "classical",
};

const PQ_KEM_TOKENS = ["mlkem", "kyber", "sntrup", "ntruprime", "frodokem", "bike", "hqc", "mceliece"];
const CLASSICAL_KEX_TOKENS = ["x25519", "x448", "curve25519", "curve448", "secp", "prime256", "brainpool",
                              "p256", "p384", "p521", "nistp", "ecp", "ecdh", "modp", "ffdhe"];

// Which GUI parameter holds the key exchange, per protocol family — the
// same field the backend reads (expected.kex for TLS/SSH, ike_sa.kex for
// IPsec, expected2.kex for ProxyJump hop #2).
const KEX_FIELD_BY_FAMILY = { tls: "curve", ssh: "kex", ipsec: "dh1" };

function kexPQPosture(kex) {
  // A "Not applicable — ..." curve (static RSA / finite-field DHE, see
  // tlsCurveOptionsFor) is dropped from the payload by buildExpectedPayload,
  // so the backend sees no kex at all: treat it the same way here.
  if (!kex || isNotApplicable(kex)) return PQ_POSTURE.CLASSICAL;
  const name = kex.split(" (")[0];
  const norm = name.toLowerCase().replace(/[-_. ]/g, "");
  if (!PQ_KEM_TOKENS.some(tok => norm.includes(tok))) return PQ_POSTURE.CLASSICAL;
  if (CLASSICAL_KEX_TOKENS.some(tok => norm.includes(tok))) return PQ_POSTURE.HYBRID;
  return PQ_POSTURE.NATIVE;
}

// Posture of the expected profile: context #1 (all use cases) or, for the
// SSH ProxyJump, context #2 (ClientExt ↔ AppServer, key "kex2").
function derivePQPosture(uc, ctx2 = false) {
  if (ctx2) return kexPQPosture((uc.selected2 || {}).kex2);
  return kexPQPosture((uc.selected || {})[KEX_FIELD_BY_FAMILY[uc.protoFamily]]);
}

const PQ_POSTURE_BADGE = {
  [PQ_POSTURE.NATIVE]:    { cls: "pq-native",  icon: "ti-shield-check-filled", label: "Native PQ" },
  [PQ_POSTURE.HYBRID]:    { cls: "pq-hybrid",  icon: "ti-shield-half",         label: "Hybrid classical+PQ" },
  [PQ_POSTURE.CLASSICAL]: { cls: "pq-classic", icon: "ti-shield",              label: "Classical" },
};

function pqBadgeHtml(posture) {
  const b = PQ_POSTURE_BADGE[posture] || PQ_POSTURE_BADGE[PQ_POSTURE.CLASSICAL];
  return `<span class="pq-posture-badge ${b.cls}">
    <i class="ti ${b.icon}"></i>${b.label}
  </span>`;
}

function computeQuantumRiskPreview(uc) {
  const shelf = parseInt((uc.selectedGovernance || {}).shelf_time_days, 10) || 0;
  // Posture of the expected key exchange — same rule and same field the
  // backend uses in _compute_quantum_risk (preview only).
  const pq = derivePQPosture(uc);
  const longLived = shelf >= QUANTUM_RISK_SHELF_THRESHOLD_DAYS;
  const classicalOnly = pq === PQ_POSTURE.CLASSICAL;
  const atRisk = longLived && classicalOnly;
  return { atRisk, shelf, pq, longLived };
}

// Same matrix as graph_writer._GOVERNANCE_RISK_MATRIX — duplicated here
// only for the client-side preview (same relationship as the quantum
// heuristic above, which duplicates QUANTUM_RISK_SHELF_THRESHOLD_DAYS for
// the same reason): the value written to the graph is always the one
// computed by the backend in _compute_governance_risk(), this is only a
// preview before saving. If the two drift apart it's a bug to fix in
// both places, not an alternative source of truth.
const GOVERNANCE_RISK_MATRIX = {
  "low|public": "LOW",          "low|internal": "LOW",
  "low|confidential": "MEDIUM", "low|critical": "MEDIUM",
  "medium|public": "LOW",       "medium|internal": "MEDIUM",
  "medium|confidential": "MEDIUM", "medium|critical": "HIGH",
  "high|public": "MEDIUM",      "high|internal": "MEDIUM",
  "high|confidential": "HIGH",  "high|critical": "CRITICAL",
};

function computeGovernanceRiskPreview(uc) {
  const gov = uc.selectedGovernance || {};
  const criticality = gov.criticality;
  const sensitivity = gov.data_sensitivity;
  if (!criticality || !sensitivity) {
    return { level: "UNKNOWN", criticality, sensitivity };
  }
  const level = GOVERNANCE_RISK_MATRIX[`${criticality}|${sensitivity}`] || "UNKNOWN";
  return { level, criticality, sensitivity };
}

function buildExpectedPayload(uc) {
  const fieldMap = EXPECTED_FIELD_MAP[uc.id] || {};
  const expected = {};
  for (const [guiKey, expectedKey] of Object.entries(fieldMap)) {
    if (!expectedKey) continue;
    const val = uc.selected[guiKey];
    // A "Not applicable — ..." value (see tlsCurveOptionsFor in data.js:
    // it appears when the chosen cipher suite is static RSA key transport
    // or finite-field DHE, contexts in which no elliptic curve is
    // negotiated) is a descriptive sentence for the operator, not an
    // algorithm name — writing it as expected.kex would expose it to the
    // comparator as a real but unrecognized value, when the correct
    // representation is simply "no KEX declared for this use case" (same
    // treatment as a field never filled in).
    if (val !== undefined && !isNotApplicable(val)) {
      expected[expectedKey] = val;
    }
  }
  // mutual_auth / client_cert_required derived from boolean-like parameters
  if (uc.selected.client_auth) {
    expected.mutual_auth = uc.selected.client_auth.includes("mTLS");
    expected.client_cert_required = uc.selected.client_auth.includes("mTLS");
  }
  // mtls_policy (service_mesh, Istio style): only STRICT guarantees mTLS
  // deterministically on every connection — it is the only value from
  // which a clear-cut, verifiable expectation can be derived. PERMISSIVE
  // explicitly accepts both mTLS and plaintext (no single correct
  // expectation to declare), DISABLE denies mTLS but declaring
  // "mutual_auth: false" as a requirement is not a pattern
  // cmp_boolean_implication evaluates in this system (same principle
  // already applied to pfs_capable for the Child SA: we compare a required
  // capability/requirement, never its explicit absence). Before this
  // addition, a service mesh declared "STRICT" in the GUI never produced a
  // comparable expectation: the most relevant security property for a
  // zero-trust architecture — is mTLS really enforced? — stayed declared
  // but never verified against observation.
  if (uc.selected.mtls_policy === "STRICT") {
    expected.mutual_auth = true;
    expected.client_cert_required = true;
  }
  // has_pfs: same treatment as mutual_auth — the GUI parameter
  // "Required"/"Not required" is a string, the Expected field is a real
  // boolean. TLS only: IPsec use cases reuse the "pfs" key with an
  // entirely different vocabulary ("ECP_384 (group dedicated to rekey)"),
  // handled separately by buildIpsecSubProfiles.
  if (uc.protoFamily === "tls" && uc.selected.pfs !== undefined) {
    expected.has_pfs = uc.selected.pfs === "Required";
  }
  if (uc.selected.rotation) {
    const match = uc.selected.rotation.match(/(\d+)h/);
    expected.cert_rotation_hours = match ? parseInt(match[1]) : (uc.selected.rotation.includes("24h") ? 24 : null);
  }
  // Lifecycle & Data Governance: direct mapping, keys already aligned
  // with the Expected node (see comment above buildExpectedPayload).
  const gov = uc.selectedGovernance || {};
  if (gov.data_sensitivity) expected.data_sensitivity = gov.data_sensitivity;
  // pq_readiness of the expected key exchange. Sent for validation and
  // for the Cypher preview only: the backend recomputes it from kex with
  // the same rule (graph_writer._derive_expected_pq_postures).
  expected.pq_readiness = derivePQPosture(uc);
  return expected;
}

// IKE SA / Child SA sub-profiles — IPsec use cases only
// (protoFamily === "ipsec"). For every other use case it returns
// {ike_sa: null, child_sa: null}, which the backend interprets as
// "no sub-profile to write" (see UseCaseInput in schema.py).
function buildIpsecSubProfiles(uc) {
  if (uc.protoFamily !== "ipsec") {
    return { ike_sa: null, child_sa: null };
  }
  const sel = uc.selected;
  // The "pfs" parameter carries a descriptive suffix in parentheses
  // ("ECP_384 (group dedicated to rekey)") — same pattern already used
  // on the backend for hostname hints: only the first token is extracted.
  const pfsRaw = sel.pfs || "";
  const pfsGroup = pfsRaw.split(" (")[0].trim();
  const pfsCapable = !pfsRaw.toLowerCase().includes("disabled");

  return {
    ike_sa: {
      protocol_version: sel.ike_version || null,
      cipher: sel.enc1 || null,
      mac: sel.int1 || null,
      kex: sel.dh1 || null,
      auth_method: sel.auth_method || null,
      rekey_time_seconds: sel.ike_rekey_time ? parseInt(sel.ike_rekey_time, 10) : null,
      // Posture of the IKE key exchange (dh1) — compared with the observed
      // IKE SA through IKE_SA_DIMENSIONS. Recomputed by the backend.
      pq_readiness: kexPQPosture(sel.dh1),
    },
    child_sa: {
      cipher: sel.enc2 || null,
      dh_group: pfsCapable ? pfsGroup : null,
      pfs_capable: pfsCapable,
      mode: "tunnel",
      lifetime_seconds: sel.child_sa_rekey_time ? parseInt(sel.child_sa_rekey_time, 10) : null,
    },
  };
}

function buildExpectedPayload2(uc) {
  // Builds the Expected payload for SSH context #2 (ClientExt → AppServer).
  // Fields in selected2 carry the "2" suffix (kex2, enc2, mac2, ...):
  // the same admin_ssh fieldMap is applied, reading from selected2 with
  // the suffix-stripped keys. No separate map: the backend
  // ExpectedCryptoProfile expects the same fields as expected.
  const fieldMap = EXPECTED_FIELD_MAP[uc.id] || {};
  const sel2 = uc.selected2 || {};
  const expected2 = {};
  for (const [guiKey, expectedKey] of Object.entries(fieldMap)) {
    if (!expectedKey) continue;
    // Read the key with the 2 suffix first (kex2, enc2...), then the one without
    const val = sel2[guiKey + '2'] !== undefined ? sel2[guiKey + '2'] : sel2[guiKey];
    if (val !== undefined && !isNotApplicable(val)) {
      expected2[expectedKey] = val;
    }
  }
  const gov = uc.selectedGovernance || {};
  if (gov.data_sensitivity) expected2.data_sensitivity = gov.data_sensitivity;
  expected2.pq_readiness = derivePQPosture(uc, true);
  return expected2;
}

function buildUseCasePayload(uc) {
  const gov = uc.selectedGovernance || {};
  const shelfTimeDays = parseInt(gov.shelf_time_days, 10) || uc.shelfTimeDays || 365;
  const suggestedCriticality = gov.criticality || uc.suggestedCriticality || "medium";
  const { ike_sa, child_sa } = buildIpsecSubProfiles(uc);

  // For SSH Bastion ProxyJump: include is_bastion_proxyjump=true and expected2
  // (the cryptographic profile for the second SSH hop: ClientExt → AppServer).
  // graph_writer._write_bastion_proxyjump_tx uses them to write two distinct
  // Expected nodes in the graph, one per cryptographic context.
  const isBastion = !!uc.isBastionProxyJump;
  const expected2 = isBastion ? buildExpectedPayload2(uc) : null;

  return {
    name: uc.name,
    shelf_time_days: shelfTimeDays,
    suggested_criticality: suggestedCriticality,
    rationale: uc.rationale || `Use case configured via CBOM Manager GUI for ${uc.proto}`,
    policy: {
      name: `Policy — ${uc.name}`,
      description: `Security requirements for ${uc.proto}`,
    },
    expected: buildExpectedPayload(uc),
    ike_sa,
    child_sa,
    is_bastion_proxyjump: isBastion,
    expected2,
    // Readonly assets (virtual/dynamic IP, e.g. clientext in API Gateway)
    // are not declared in the graph as use-case assets: their IP changes
    // on every connection and there is no stable Asset node to attach an
    // Observed profile to. The TLS terminator (apigw) is the
    // cryptographically relevant asset to track.
    // Readonly assets are excluded from the API payload but included in
    // the Cypher preview with an explanatory comment, for documentation.
    assets: uc.assets.filter(a => !a.readonly).map(a => ({
      name: a.name,
      role: a.role,
      ip: a.ip,
      hostname: a.host,
      zone: zoneOf(a),
      criticality: (ASSET_DEFAULTS[a.name] && ASSET_DEFAULTS[a.name].criticality) || "medium",
    })),
    service_name: uc.proto,
    service_protocol: uc.proto,
    service_protocol_family: uc.protoFamily,
  };
}

// ─── RENDERING ───────────────────────────────────────────────────────────

// Returns true if an option string contains a quantum-safe marker.
// QUANTUM_SAFE_MARKERS is defined in data.js.
function isQuantumSafe(optionStr) {
  if (typeof QUANTUM_SAFE_MARKERS === 'undefined') return false;
  return QUANTUM_SAFE_MARKERS.some(m => optionStr.includes(m));
}

// Returns true if the selected cipher/enc is AEAD (built-in authentication):
// for these primitives the MAC panel is not separately configurable.
function isAEAD(val) {
  if (!val) return false;
  const v = val.toUpperCase();
  return v.includes('GCM') || v.includes('POLY1305') || v.includes('CCM') ||
         v.includes('CHACHA20') || (v.includes('GCM_16') && !v.includes('CBC'));
}

// Returns true if the field is a MAC / integrity field that becomes conditional.
function isMACField(key) {
  // int1 is the IKEv2 PRF (Pseudo-Random Function) — independent of the
  // channel encryption, always configurable even with an AEAD cipher.
  // It must never be disabled by the AEAD logic, which only concerns the
  // separate MAC of non-AEAD ciphers (e.g. AES-CBC + HMAC).
  return key === 'mac' || key === 'mac2';
}

// Returns the key of the associated cipher (if any) to decide whether the
// MAC is conditional. Each use case may name the cipher with different
// keys (enc, enc1, cipher, cipher12...).
function cipherKeyFor(uc) {
  const keys = ['cipher', 'enc', 'enc1', 'cipher12'];
  for (const k of keys) {
    if (uc.selected[k] !== undefined) return k;
  }
  return null;
}

function renderParams(uc) {
  const grid = document.getElementById('param-grid');
  const cipherKey = cipherKeyFor(uc);
  const currentCipher = cipherKey ? uc.selected[cipherKey] : null;
  const cipherIsAEAD = isAEAD(currentCipher);

  grid.innerHTML = uc.params.map(p => {
    const options = typeof p.options === 'function' ? p.options(uc.selected) : p.options;
    const recommended = typeof p.recommended === 'function' ? p.recommended(uc.selected) : p.recommended;
    const dev = uc.selected[p.key] !== recommended;
    const notApplicable = options.length === 1 && isNotApplicable(options[0]);

    // MAC/integrity panel disabled when the cipher is AEAD:
    // authentication is already built into the primitive, configuring it
    // separately makes no sense and could be misleading.
    const macDisabledByAEAD = isMACField(p.key) && cipherIsAEAD;
    const disabled = notApplicable || macDisabledByAEAD;

    let boxClass = '';
    if (notApplicable || macDisabledByAEAD) {
      boxClass = ' not-applicable';
    } else if (dev) {
      boxClass = ' deviant';
    }
    // Highlight as quantum-safe if the current value is PQ/hybrid
    if (!disabled && !dev && isQuantumSafe(uc.selected[p.key] || '')) {
      boxClass = ' quantum-safe';
    }

    const title = macDisabledByAEAD
      ? 'Authentication built into the AEAD primitive — not separately configurable'
      : (notApplicable ? 'Not applicable with the selected cipher suite' : '');

    // Options: <option> with a quantum-safe marker on PQ ones
    const optHtml = options.map(o => {
      const qs = isQuantumSafe(o) ? ' data-qs="1"' : '';
      return `<option${uc.selected[p.key] === o ? ' selected' : ''}${qs}>${o}</option>`;
    }).join('');

    // For MAC fields disabled by AEAD: disabled param-box with a hover
    // tooltip explaining why — less invasive than a dedicated card, yet
    // still conveys the AEAD semantics to the operator.
    if (macDisabledByAEAD) {
      const cipherName = (uc.selected[cipherKey] || currentCipher || '').split(' ')[0];
      const aeadTooltip = `Built into ${cipherName} — AEAD primitives provide authentication and integrity by construction. No separate MAC is negotiated or applied (RFC 4253 §6.4).`;
      return `<div class="param-box not-applicable param-box-aead" title="${aeadTooltip}">
        <label>${p.label} <span class="aead-inline-badge">AEAD</span></label>
        <select disabled>
          <option>Built into the cipher</option>
        </select>
      </div>`;
    }

    return `<div class="param-box${boxClass}"${title ? ` title="${title}"` : ''}>
      <label>${p.label}${!disabled && isQuantumSafe(uc.selected[p.key] || '') ? ' <span class="qs-badge">PQ</span>' : ''}</label>
      <select onchange="updateParam('${p.key}', this.value)"${disabled ? ' disabled' : ''}>
        ${optHtml}
      </select>
    </div>`;
  }).join('');

  // ── SSH context #2 for ProxyJump (ClientExt → AppServer) ──────────────
  const grid2Container = document.getElementById('param-grid-2-section');
  if (uc.isBastionProxyJump && uc.params2 && grid2Container) {
    grid2Container.style.display = '';
    const grid2 = document.getElementById('param-grid-2');
    if (grid2) {
      const cipher2AEAD = isAEAD((uc.selected2 || {}).enc2);
      grid2.innerHTML = uc.params2.map(p => {
        const sel2 = uc.selected2 || {};
        const dev = sel2[p.key] !== p.recommended;
        const macD = isMACField(p.key.replace(/2$/, '')) && cipher2AEAD;
        const disabled = macD;
        let boxClass = disabled ? ' not-applicable' : dev ? ' deviant' : '';
        if (!disabled && !dev && isQuantumSafe(sel2[p.key] || '')) boxClass = ' quantum-safe';
        const optHtml = p.options.map(o => {
          const qs = isQuantumSafe(o) ? ' data-qs="1"' : '';
          return `<option${sel2[p.key] === o ? ' selected' : ''}${qs}>${o}</option>`;
        }).join('');
        return `<div class="param-box${boxClass}">
          <label>${p.label}${!disabled && isQuantumSafe(sel2[p.key] || '') ? ' <span class="qs-badge">PQ</span>' : ''}</label>
          <select onchange="updateParam2('${p.key}', this.value)"${disabled ? ' disabled' : ''}>
            ${optHtml}
          </select>
        </div>`;
      }).join('');
    }
  } else if (grid2Container) {
    grid2Container.style.display = 'none';
  }
}

function renderGovernance(uc) {
  const grid = document.getElementById('governance-grid');
  if (!grid) return; // markup not yet updated in index.html
  grid.innerHTML = uc.governance.map(p => {
    const dev = uc.selectedGovernance[p.key] !== p.recommended;
    return `<div class="param-box${dev ? ' deviant' : ''}">
      <label>${p.label}</label>
      <select onchange="updateGovernance('${p.key}', this.value)">
        ${p.options.map(o => `<option${uc.selectedGovernance[p.key] === o ? ' selected' : ''}>${o}</option>`).join('')}
      </select>
    </div>`;
  }).join('');

  const risk = computeQuantumRiskPreview(uc);
  const badge = document.getElementById('quantum-risk-badge');
  if (!badge) return;

  // Derived PQC posture badge — always visible, updated in real time
  const pqBadge = pqBadgeHtml(risk.pq);

  if (risk.atRisk) {
    badge.innerHTML = `
      <div class="pq-posture-row">${pqBadge}
        <span class="pq-posture-label">Expected PQC posture — derived from the expected key exchange</span>
      </div>
      <div class="risk-badge risk-warn" style="margin-top:10px">
        <i class="ti ti-alert-triangle"></i>
        <div><strong>Policy: possible harvest-now-decrypt-later exposure (Mosca's theorem)</strong>
        Shelf time of ${risk.shelf} days with a "${risk.pq}" key exchange: traffic recorded today may
        need to stay confidential longer than classical key establishment can withstand a quantum adversary.
        Replace the key exchange with a hybrid or native PQ one.
        <br><em>Preview of the expected (policy) side. The observed exposure — same shelf time, worst key
        exchange over every observed session — is computed on ingest: see the Expected/Observed comparison tab.</em></div>
      </div>`;
  } else {
    badge.innerHTML = `
      <div class="pq-posture-row">${pqBadge}
        <span class="pq-posture-label">Expected PQC posture — derived from the expected key exchange</span>
      </div>
      <div class="risk-badge risk-ok" style="margin-top:10px">
        <i class="ti ti-shield-check"></i>
        <div><strong>Policy: no quantum exposure detected by the heuristic</strong>
      Current combination of shelf time (${risk.shelf} days) and expected key-exchange posture ("${risk.pq || '—'}")
      is within the configured alert thresholds.
      <br><em>Preview of the expected (policy) side. The observed exposure — same shelf time, worst key
      exchange over every observed session — is computed on ingest: see the Expected/Observed comparison tab.</em></div>
    </div>`;
  }

  // Context (governance) risk: orthogonal to the quantum risk above —
  // that one measures a technical property of encryption over time,
  // this one measures how much a potential technical gap matters given
  // what the use case protects (operational criticality × data sensitivity).
  // Same value that _compute_governance_risk() writes on UseCase in
  // graph_writer.py when saving — here only a preview.
  const govRiskBadge = document.getElementById('governance-risk-badge');
  if (govRiskBadge) {
    const govRisk = computeGovernanceRiskPreview(uc);
    const GOV_RISK_UI = {
      LOW:      { cls: "risk-low",      icon: "ti-shield-check",   label: "Context risk: LOW" },
      MEDIUM:   { cls: "risk-medium",   icon: "ti-shield-half",    label: "Context risk: MEDIUM" },
      HIGH:     { cls: "risk-high",     icon: "ti-shield-exclamation", label: "Context risk: HIGH" },
      CRITICAL: { cls: "risk-critical", icon: "ti-alert-triangle", label: "Context risk: CRITICAL" },
      UNKNOWN:  { cls: "risk-unknown",  icon: "ti-help-circle",    label: "Context risk: cannot be computed" },
    };
    const ui = GOV_RISK_UI[govRisk.level] || GOV_RISK_UI.UNKNOWN;
    const detail = govRisk.level === "UNKNOWN"
      ? "Set both use-case criticality and data sensitivity to compute it."
      : `Use-case criticality "${govRisk.criticality}" combined with data sensitivity "${govRisk.sensitivity}". Used to prioritize remediation of technical findings on this use case — it does not change their cryptographic severity.`;
    govRiskBadge.innerHTML = `
      <div class="risk-badge ${ui.cls}" style="margin-top:10px">
        <i class="ti ${ui.icon}"></i>
        <div><strong>${ui.label}</strong>${detail}</div>
      </div>`;
  }
}

// ─── NETWORK TOPOLOGY — zone layout and metadata ────────────────────────────
// "Topology & Assets" tab: shows the zones/partitions of the Kathará
// topology involved in the current use case, the hosts residing in them
// and the application communication channel between them. The
// zone↔use-case structure is declared here (+ ASSET_DEFAULTS/zoneOf) and
// stays fixed; the only thing the operator can change is each host's
// network parameters (hostname, IP), in the HTML panels below the map —
// never the zone membership or the association with the use case.
const ZONE_LAYOUT = {
  internet:     { label: 'Internet',     x: 20,  y: 70,  w: 110, h: 80,  fill: '#fef3c7', stroke: '#f59e0b', tx: '#92400e', icon: 'globe',    desc: 'Public, untrusted network.' },
  dmz:          { label: 'DMZ',          x: 150, y: 40,  w: 130, h: 110, fill: '#fee2e2', stroke: '#ef4444', tx: '#991b1b', icon: 'shield',   desc: 'Demilitarized zone — exposed services.' },
  internal_lan: { label: 'Internal LAN', x: 300, y: 40,  w: 140, h: 110, fill: '#dbeafe', stroke: '#3b82f6', tx: '#1e40af', icon: 'building', desc: 'Internal corporate LAN.' },
  mgmt:         { label: 'Management',   x: 460, y: 40,  w: 130, h: 110, fill: '#f3e8ff', stroke: '#a855f7', tx: '#6b21a8', icon: 'gear',     desc: 'Administration network.' },
  service_mesh: { label: 'Service Mesh', x: 300, y: 170, w: 140, h: 80,  fill: '#d1fae5', stroke: '#10b981', tx: '#065f46', icon: 'mesh',     desc: 'Internal microservice mesh.' },
  vpn_tunnel:   { label: 'VPN Tunnel',   x: 150, y: 170, w: 130, h: 80,  fill: '#e0f2fe', stroke: '#0ea5e9', tx: '#0c4a6e', icon: 'lock',     desc: 'Encrypted point-to-point tunnel.' },
  remote_site:  { label: 'Remote Site',  x: 460, y: 170, w: 130, h: 80,  fill: '#f0fdf4', stroke: '#22c55e', tx: '#14532d', icon: 'pin',      desc: 'Remote site/endpoint.' },
};

// Hand-drawn (stroke-only) vector micro-icons, one per zone type — avoids
// depending on a webfont inside the SVG (tabler-icons glyphs cannot be
// reliably referenced as <text>) and gives each zone a symbol that is
// distinguishable at a glance on the map.
function zoneIconSVG(kind, cx, cy, color) {
  switch (kind) {
    case 'globe':
      return `<g stroke="${color}" stroke-width="1.3" fill="none">
        <circle cx="${cx}" cy="${cy}" r="8"/>
        <ellipse cx="${cx}" cy="${cy}" rx="3.1" ry="8"/>
        <line x1="${cx-8}" y1="${cy}" x2="${cx+8}" y2="${cy}"/>
        <path d="M${cx-7},${cy-4} Q${cx},${cy-6.5} ${cx+7},${cy-4}"/>
        <path d="M${cx-7},${cy+4} Q${cx},${cy+6.5} ${cx+7},${cy+4}"/>
      </g>`;
    case 'shield':
      return `<g stroke="${color}" stroke-width="1.3" fill="none">
        <path d="M${cx},${cy-8} L${cx+6.5},${cy-5} L${cx+6.5},${cy+2} Q${cx+6.5},${cy+7} ${cx},${cy+9}
                 Q${cx-6.5},${cy+7} ${cx-6.5},${cy+2} L${cx-6.5},${cy-5} Z"/>
        <path d="M${cx-3},${cy} l2.3,2.5 l4.4,-5.2"/>
      </g>`;
    case 'building':
      return `<g stroke="${color}" stroke-width="1.3" fill="none">
        <rect x="${cx-6}" y="${cy-9}" width="12" height="17" rx="1"/>
        <line x1="${cx-3.5}" y1="${cy-5.5}" x2="${cx-1.5}" y2="${cy-5.5}"/>
        <line x1="${cx+1.5}" y1="${cy-5.5}" x2="${cx+3.5}" y2="${cy-5.5}"/>
        <line x1="${cx-3.5}" y1="${cy-1}" x2="${cx-1.5}" y2="${cy-1}"/>
        <line x1="${cx+1.5}" y1="${cy-1}" x2="${cx+3.5}" y2="${cy-1}"/>
        <line x1="${cx-2}" y1="${cy+4.5}" x2="${cx+2}" y2="${cy+4.5}"/>
      </g>`;
    case 'gear':
      return `<g stroke="${color}" stroke-width="1.3" fill="none">
        <circle cx="${cx}" cy="${cy}" r="3.6"/>
        <circle cx="${cx}" cy="${cy}" r="7.8" stroke-dasharray="2.4,2.8"/>
      </g>`;
    case 'mesh':
      return `<g stroke="${color}" stroke-width="1.1" fill="${color}">
        <line x1="${cx}" y1="${cy-6}" x2="${cx-6}" y2="${cy+5}"/>
        <line x1="${cx}" y1="${cy-6}" x2="${cx+6}" y2="${cy+5}"/>
        <line x1="${cx-6}" y1="${cy+5}" x2="${cx+6}" y2="${cy+5}"/>
        <circle cx="${cx}" cy="${cy-6}" r="2"/>
        <circle cx="${cx-6}" cy="${cy+5}" r="2"/>
        <circle cx="${cx+6}" cy="${cy+5}" r="2"/>
      </g>`;
    case 'lock':
      return `<g stroke="${color}" stroke-width="1.3" fill="none">
        <rect x="${cx-5.5}" y="${cy-1}" width="11" height="9" rx="1.5"/>
        <path d="M${cx-3.2},${cy-1} v-3 a3.2,3.2 0 0 1 6.4,0 v3"/>
      </g>`;
    case 'pin':
      return `<g>
        <path d="M${cx},${cy+8} C${cx-6},${cy} ${cx-6},${cy-6} ${cx},${cy-8}
                 C${cx+6},${cy-6} ${cx+6},${cy} ${cx},${cy+8} Z"
              stroke="${color}" stroke-width="1.2" fill="none"/>
        <circle cx="${cx}" cy="${cy-2.5}" r="2" fill="${color}"/>
      </g>`;
    default:
      return '';
  }
}

// ─── TOPOLOGY MAP — interactive-on-change, not editable in place ─────────────
// Live reflection of the declared Kathará topology (ZONE_LAYOUT/ASSET_DEFAULTS
// + any explicit zone on the asset, via zoneOf()): which zones are involved
// in the current use case, which hosts reside in them and the application
// communication channel connecting them. It updates on every use-case
// change and every hostname/IP edit (renderTopologyAssets), but editing
// network parameters remains an action on the HTML panels below, never a
// direct edit inside the SVG.

// ─── SESSION DIAGRAM (point-to-point connection) ────────────────────────────
// Graphically represents, for the selected use case, the communication
// relationship between the two assets delivering it: [Asset A] ── protocol /
// use case ── [Asset B]. Purely relational — it conveys WHO talks to WHOM
// and WHAT we want them to negotiate, not an observed state: that lives
// in the "Expected/Observed comparison" tab, fed by Zeek.
//
// The per-asset icon is derived heuristically from role/name (there is no,
// and there must not be, a dedicated "type" field in data.js: adding one
// for the sole decorative purpose of the diagram would introduce yet
// another source of drift to keep in sync by hand).
const PROTO_FAMILY_ICON = { ipsec: "ti-lock", ssh: "ti-terminal-2", tls: "ti-shield-lock" };

function assetIconFor(asset) {
  const t = `${asset.role || ""} ${asset.name || ""}`.toLowerCase();
  if (t.includes("bastion") || t.includes("jump")) return "ti-terminal-2";
  if (t.includes("client") || t.includes("remote") || t.includes("road warrior")) return "ti-device-laptop";
  if (t.includes("firewall")) return "ti-shield-lock";
  if (t.includes("microservice") || /\bsvc/.test(t)) return "ti-topology-star";
  if (t.includes("mail")) return "ti-mail";
  if (t.includes("log")) return "ti-file-text";
  if (t.includes("backup")) return "ti-database";
  if (t.includes("gateway") || /\bgw\b/.test(t)) return "ti-router";
  return "ti-server";
}

function renderSessionDiagram(uc) {
  const el = document.getElementById('session-diagram');
  if (!el) return;
  if (!uc.assets || uc.assets.length < 2) { el.innerHTML = ''; return; }

  el.className = `session-diagram family-${uc.protoFamily}`;
  const protoIcon = PROTO_FAMILY_ICON[uc.protoFamily] || 'ti-shield-lock';

  // ── ProxyJump (SSH Bastion): three nodes, two distinct SSH channels ─────
  if (uc.isBastionProxyJump && uc.assets.length >= 3) {
    const [client, bastion, target] = uc.assets;
    el.innerHTML = `
      <div class="sd-node">
        <div class="sd-node-icon"><i class="ti ${assetIconFor(client)}"></i></div>
        <div class="sd-node-body">
          <span class="sd-node-name">${client.name}</span>
          <span class="sd-node-role">${client.role}</span>
          <span class="sd-node-meta">${client.host} · ${client.ip}</span>
        </div>
      </div>
      <div class="sd-link">
        <div class="sd-badge sd-badge-ctx1"><i class="ti ti-terminal-2"></i>SSH #1 — clientext ↔ bastion</div>
        <div class="sd-track">
          <span class="sd-endpoint sd-endpoint-a"></span>
          <span class="sd-endpoint sd-endpoint-b"></span>
          <span class="sd-packet sd-packet-fwd"></span>
          <span class="sd-packet sd-packet-back"></span>
        </div>
        <div class="sd-badge sd-badge-usecase" style="font-size:10px">
          <i class="ti ti-key"></i>Independent KEX + authentication
        </div>
      </div>
      <div class="sd-node sd-node-relay">
        <div class="sd-node-icon sd-node-icon-relay"><i class="ti ti-door-enter"></i></div>
        <div class="sd-node-body">
          <span class="sd-node-name">${bastion.name}</span>
          <span class="sd-relay-label">TCP forwarder / jump server</span>
          <span class="sd-node-meta">${bastion.host} · ${bastion.ip}</span>
          <span class="sd-relay-note">SSH #2 bytes pass through opaque — the bastion does not decrypt them</span>
        </div>
      </div>
      <div class="sd-link">
        <div class="sd-badge sd-badge-ctx2"><i class="ti ti-terminal-2"></i>SSH #2 — clientext ↔ appserver</div>
        <div class="sd-track">
          <span class="sd-endpoint sd-endpoint-a"></span>
          <span class="sd-endpoint sd-endpoint-b"></span>
          <span class="sd-packet sd-packet-fwd"></span>
          <span class="sd-packet sd-packet-back"></span>
        </div>
        <div class="sd-badge sd-badge-usecase" style="font-size:10px">
          <i class="ti ti-key"></i>end-to-end client → appserver
        </div>
      </div>
      <div class="sd-node">
        <div class="sd-node-icon"><i class="ti ${assetIconFor(target)}"></i></div>
        <div class="sd-node-body">
          <span class="sd-node-name">${target.name}</span>
          <span class="sd-node-role">${target.role}</span>
          <span class="sd-node-meta">${target.host} · ${target.ip}</span>
        </div>
      </div>`;
    return;
  }

  // ── Standard (two nodes) ───────────────────────────────────────────────
  const [a, b] = uc.assets;
  el.innerHTML = `
    <div class="sd-node">
      <div class="sd-node-icon"><i class="ti ${assetIconFor(a)}"></i></div>
      <div class="sd-node-body">
        <span class="sd-node-name">${a.name}</span>
        <span class="sd-node-role">${a.role}</span>
        <span class="sd-node-meta">${a.host} · ${a.ip}</span>
      </div>
    </div>
    <div class="sd-link">
      <div class="sd-badge sd-badge-proto" title="Protocol of this session">
        <i class="ti ${protoIcon}"></i>${uc.proto}
      </div>
      <div class="sd-track">
        <span class="sd-endpoint sd-endpoint-a"></span>
        <span class="sd-endpoint sd-endpoint-b"></span>
        <span class="sd-packet sd-packet-fwd" title="Proposal"></span>
        <span class="sd-packet sd-packet-back" title="Negotiated / agreement"></span>
      </div>
      <div class="sd-badge sd-badge-usecase" title="Infrastructure use case">
        <i class="ti ti-route"></i>${uc.name}
      </div>
      <div class="sd-legend">
        <span><i class="sd-dot sd-dot-fwd"></i>proposal</span>
        <span><i class="sd-dot sd-dot-back"></i>negotiated/agreement</span>
      </div>
    </div>
    <div class="sd-node">
      <div class="sd-node-icon"><i class="ti ${assetIconFor(b)}"></i></div>
      <div class="sd-node-body">
        <span class="sd-node-name">${b.name}</span>
        <span class="sd-node-role">${b.role}</span>
        <span class="sd-node-meta">${b.host} · ${b.ip}</span>
      </div>
    </div>`;
}

// Groups the use case's assets by network zone (preserving the order in
// which zones first appear) and renders one panel per zone: the
// zone/partition and the association with the use case stay fixed
// (derived from zoneOf()), only each host's hostname and IP are editable.
// The index passed to updateAsset/removeAsset is always the GLOBAL one in
// uc.assets, not the group-local one — necessary because both functions
// index the original array directly.
function renderTopologyAssets(uc) {
  const container = document.getElementById('topology-zone-panels');
  if (!container) return;

  const groups = [];
  uc.assets.forEach((a, i) => {
    const zone = zoneOf(a);
    let g = groups.find(g => g.zone === zone);
    if (!g) { g = { zone, items: [] }; groups.push(g); }
    g.items.push(i);
  });

  container.innerHTML = groups.map(g => {
    const meta = ZONE_LAYOUT[g.zone] || ZONE_LAYOUT.internal_lan;
    const rows = g.items.map(i => {
      const a = uc.assets[i];
      // Read-only asset: endpoint whose IP is assigned dynamically
      // (e.g. clientext with a virtual IP from the VPN pool) — not editable in the GUI.
      if (a.readonly) {
        return `
        <div class="asset-row asset-row-readonly">
          <div class="asset-icon" style="border-color:${meta.stroke}33">
            <i class="ti ${assetIconFor(a)}" style="color:${meta.stroke}"></i>
          </div>
          <div class="asset-info">
            <p>${a.name}</p>
            <span>${a.role}</span>
            ${a.note ? `<span class="asset-readonly-note"><i class="ti ti-info-circle"></i>${a.note}</span>` : ''}
          </div>
          <div class="asset-fields">
            <input class="host-field" value="${a.host}" placeholder="hostname" disabled>
            <input class="ip-field" value="${a.ip}" placeholder="IP" disabled>
          </div>
        </div>`;
      }
      return `
      <div class="asset-row">
        <div class="asset-icon" style="border-color:${meta.stroke}33">
          <i class="ti ${assetIconFor(a)}" style="color:${meta.stroke}"></i>
        </div>
        <div class="asset-info"><p>${a.name}</p><span>${a.role}</span></div>
        <div class="asset-fields">
          <input class="host-field" value="${a.host}" placeholder="hostname"
                 onchange="updateAsset(${i}, 'host', this.value)">
          <input class="ip-field" value="${a.ip}" placeholder="IP"
                 onchange="updateAsset(${i}, 'ip', this.value)">
          <button class="asset-delete" onclick="removeAsset(${i})" title="Remove host">
            <i class="ti ti-trash"></i>
          </button>
        </div>
      </div>`;
    }).join('');
    return `
      <div class="zone-panel" style="--zone-fill:${meta.fill};--zone-stroke:${meta.stroke};--zone-tx:${meta.tx}">
        <div class="zone-panel-header">
          <span class="zone-panel-dot"></span>
          <div class="zone-panel-title">
            <strong>${meta.label}</strong>
            <span>${meta.desc}</span>
          </div>
          <span class="zone-panel-count">${g.items.length} ${g.items.length === 1 ? 'host' : 'hosts'}</span>
        </div>
        <div class="zone-panel-body">${rows}</div>
      </div>`;
  }).join('');
}

function renderFindingsPlaceholder(checked) {
  const message = checked
    ? { title: "No deviations detected.", sub: "Comparison completed successfully: the observed profiles comply with the expected policy on all comparable dimensions." }
    : { title: "No findings available.", sub: "Start the Kathará scenario to populate the observed cryptographic profiles and compare them against the configured policy." };
  document.getElementById('findings-list').innerHTML = `
    <div class="finding-placeholder">
      <i class="ti ${checked ? 'ti-shield-check' : 'ti-radar'}"></i>
      <p>${message.title}</p>
      <p class="placeholder-sub">${message.sub}</p>
      <button class="btn" onclick="loadFindings()">
        <i class="ti ti-refresh"></i> Load findings from Neo4j
      </button>
    </div>`;
}

// Same readable-label table used on the backend
// (comparison_view.py _LABELS / _SCOPE_LABELS) — duplicated here because
// the frontend has no direct access to the Python module, but the names
// stay identical: an operator moving from the Comparison tab to the
// Findings tab should not have to relearn a different vocabulary for the
// same concept.
const FINDING_ATTRIBUTE_LABELS = {
  protocol_version: "Protocol version",
  kex: "Key exchange (KEX)",
  cipher: "Encryption",
  mac: "Integrity (MAC)",
  host_key: "Host/identity key",
  has_pfs: "Perfect Forward Secrecy",
  auth_method: "Authentication method",
  dh_group: "DH group (data plane)",
  pfs_capable: "PFS configured",
  rekey_time_seconds: "Rekey time (s)",
  lifetime_seconds: "Child SA lifetime (s)",
  pq_readiness: "PQC posture",
};
const FINDING_SCOPE_LABELS = { ike_sa: "IKE SA", child_sa: "Child SA" };

function formatFindingAttribute(raw) {
  const [scope, attr] = raw.includes(".") ? raw.split(".") : [null, raw];
  const label = FINDING_ATTRIBUTE_LABELS[attr] || attr;
  return scope ? `${FINDING_SCOPE_LABELS[scope] || scope} · ${label}` : label;
}

function formatFindingDate(iso) {
  if (!iso) return "date not available";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function renderFindingsList(findings, checked) {
  if (!findings || findings.length === 0) {
    renderFindingsPlaceholder(checked);
    return;
  }
  document.getElementById('findings-list').innerHTML = findings.map(f => {
    const type = f.severity >= 0.7 ? 'fail' : 'warn';
    const icon = type === 'fail' ? 'ti-x' : 'ti-alert-triangle';
    const pct = Math.round((f.severity || 0) * 100);
    return `<div class="finding finding-${type}">
      <i class="ti ${icon} find-icon"></i>
      <div class="finding-body">
        <div class="finding-head">
          <span class="finding-title">${formatFindingAttribute(f.attribute)}</span>
          <span class="finding-asset"><i class="ti ti-server"></i>${f.asset}</span>
          <span class="finding-severity finding-severity-${type}">${pct}%</span>
        </div>
        <div class="finding-values">
          <span><span class="finding-values-label">Configured</span> ${f.expected}</span>
          <span><span class="finding-values-label">Observed</span> ${f.observed}</span>
        </div>
        ${f.detail ? `<p class="finding-detail">${f.detail}</p>` : ''}
        <span class="finding-date">${formatFindingDate(f.detected_at)}</span>
      </div>
    </div>`;
  }).join('');
}

function generateCypherPreview(uc) {
  const payload = buildUseCasePayload(uc);
  const risk = computeQuantumRiskPreview(uc);
  const govRisk = computeGovernanceRiskPreview(uc);
  const expectedProps = Object.entries(payload.expected)
    .map(([k, v]) => `  <span class="prop">${k}</span>: <span class="str">"${v}"</span>`).join(',\n');
  // Readonly assets (virtual/dynamic IP): documented in the preview but
  // not included in the API payload — they have no stable Asset node in the graph.
  const readonlyNotes = uc.assets.filter(a => a.readonly).map(a =>
    `<span class="cmt">// ${a.name} (${a.role}): virtual IP — not written to the graph</span>`
  ).join('\n');  // eslint-disable-line

    const assetMerges = payload.assets.map(a =>
    `<span class="kw">MERGE</span> (<span class="prop">${a.name}</span>:<span class="lbl">Asset</span> {name: <span class="str">"${a.name}"</span>})
  <span class="kw">SET</span> ${a.name}.ip = <span class="str">"${a.ip}"</span>, ${a.name}.hostname = <span class="str">"${a.hostname}"</span>,
      ${a.name}.zone = <span class="str">"${a.zone}"</span>, ${a.name}.criticality = <span class="str">"${a.criticality}"</span>`
  ).join('\n');
  const assetRels = payload.assets.map(a =>
    `<span class="kw">MERGE</span> (${a.name})-[:<span class="lbl">HOSTS</span>]->(svc)\n<span class="kw">MERGE</span> (${a.name})-[:<span class="lbl">EXPOSES</span>]->(exp)`
  ).join('\n');

  return `<span class="cmt">// UseCase — atomic semantic unit</span>
<span class="kw">MERGE</span> (use:<span class="lbl">UseCase</span> {name: <span class="str">"${payload.name}"</span>})
  <span class="kw">SET</span> use.shelf_time_days = <span class="prop">${payload.shelf_time_days}</span>,
      use.suggested_criticality = <span class="str">"${payload.suggested_criticality}"</span>,
      <span class="cmt">// HNDL, expected side: shelf_time_days × expected key-exchange posture (quantum_risk.py)</span>
      use.quantum_risk_expected_flag = <span class="prop">${risk.atRisk}</span>,
      <span class="cmt">// HNDL, observed side (use.quantum_risk_observed_flag): same heuristic × worst key</span>
      <span class="cmt">// exchange over every observed session — computed by the backend on ingest</span>
      <span class="cmt">// derived from suggested_criticality + expected.data_sensitivity (fixed matrix)</span>
      use.governance_risk_level = <span class="str">"${govRisk.level}"</span>

<span class="cmt">// Policy</span>
<span class="kw">MERGE</span> (pol:<span class="lbl">Policy</span> {use_case: <span class="str">"${payload.name}"</span>})
  <span class="kw">SET</span> pol.name = <span class="str">"${payload.policy.name}"</span>
<span class="kw">MERGE</span> (use)-[:<span class="lbl">REQUIRES</span>]->(pol)

<span class="cmt">// CryptoProfile:Expected — filled in from the GUI</span>
<span class="kw">MERGE</span> (exp:<span class="lbl">CryptoProfile</span>:<span class="lbl">Expected</span> {use_case: <span class="str">"${payload.name}"</span>})
  <span class="kw">SET</span> exp += {
${expectedProps}
  }

<span class="cmt">// Service</span>
<span class="kw">MERGE</span> (svc:<span class="lbl">Service</span> {service_key: <span class="str">"svc_${uc.id}"</span>})
  <span class="kw">SET</span> svc.name = <span class="str">"${payload.service_name}"</span>,
      svc.protocol = <span class="str">"${payload.service_protocol}"</span>,
      svc.protocol_family = <span class="str">"${payload.service_protocol_family}"</span>
<span class="kw">MERGE</span> (svc)-[:<span class="lbl">SERVES</span> {confidence: <span class="prop">1.0</span>}]->(use)

<span class="cmt">// Involved assets</span>
${assetMerges}
${assetRels}`;
}

// ─── BACKEND COMMUNICATION ──────────────────────────────────────────────

async function applyConfig() {
  const uc = USE_CASES[currentUC];
  const payload = buildUseCasePayload(uc);
  const btn = document.getElementById('save-btn');
  const orig = btn.innerHTML;
  btn.innerHTML = '<i class="ti ti-loader-2"></i> Saving...';
  btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/api/usecases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const result = await res.json();
    showToast(`Policy saved to Neo4j — ${result.assets_written} assets written`);
    btn.innerHTML = '<i class="ti ti-check"></i> Saved';

    // VIOLATES recomputation for this use case — it neither blocks nor
    // overrides the save toast, but if it fails it reports it explicitly:
    // a silent failure here (e.g. backend not restarted with the latest
    // /api/drift endpoint) would be indistinguishable from a bug in the
    // deviation engine, when it's only a version mismatch between the
    // running frontend and backend.
    fetch(`${API_BASE}/api/drift/${encodeURIComponent(uc.name)}`, { method: 'POST' })
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); })
      .catch(e => showToast(`Policy saved, but the automatic deviation recomputation failed (${e.message}) — open the Findings tab and reload manually`, true));
  } catch (e) {
    showToast(`Error: ${e.message}`, true);
    btn.innerHTML = '<i class="ti ti-alert-triangle"></i> Error';
  } finally {
    btn.disabled = false;
    setTimeout(() => { btn.innerHTML = orig; }, 1800);
  }

  document.getElementById('cypher-output').innerHTML = generateCypherPreview(uc);
}

async function loadFindings() {
  const uc = USE_CASES[currentUC];
  try {
    const res = await fetch(`${API_BASE}/api/findings/${encodeURIComponent(uc.name)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderFindingsList(data.findings, true);
    if (data.findings.length === 0) {
      showToast('No findings for this use case (pipeline not started yet?)');
    }
  } catch (e) {
    showToast(`Backend unreachable: ${e.message}`, true);
  }
}

// The source of truth for the operator: EVERY evaluated dimension (match,
// deviation, not_comparable), not only violations — complementary to
// loadFindings(), never a duplicate: both read the same backend
// computation (comparators.py), shown here in full instead of filtered
// on deviations only.
async function loadComparison() {
  const uc = USE_CASES[currentUC];
  try {
    const res = await fetch(`${API_BASE}/api/comparison/${encodeURIComponent(uc.name)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderComparisonTable(data.assets);
    if (!data.assets || data.assets.length === 0) {
      showToast('No observed profile for this use case (ingest not run yet?)');
    }
  } catch (e) {
    showToast(`Backend unreachable: ${e.message}`, true);
  }

  // State PERSISTED on Neo4j (quantum_risk_expected_flag and
  // governance_risk_level — written by graph_writer.py when the policy is
  // saved; quantum_risk_observed_flag — written by cbom_loader.py on
  // ingest and refreshed on save), distinct from
  // the badges in the Lifecycle & Data Governance tab: those are a live
  // preview computed on the values currently selected in the form, BEFORE
  // saving — they may differ from what is actually in the graph if the
  // form was touched without pressing "Save policy". GET /api/usecases/
  // has existed since the first backend version precisely for this (see
  // read_usecase_summary in graph_writer.py) but was never wired to any
  // GUI button.
  await loadPersistedRiskState(uc.name);
}

async function loadPersistedRiskState(usecaseName) {
  const container = document.getElementById('persisted-risk-badges');
  if (!container) return;
  try {
    const res = await fetch(`${API_BASE}/api/usecases/${encodeURIComponent(usecaseName)}`);
    if (res.status === 404) {
      container.innerHTML = `<p class="cmp-persisted-empty">Use case not yet saved to Neo4j — no persisted state to show.</p>`;
      return;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const u = data.usecase || {};

    // HNDL exposure, both sides of the same heuristic (quantum_risk.py).
    // null/undefined = not evaluable (e.g. no observed session in the last
    // ingest) — shown as such, never as "no exposure".
    // ── HNDL in the comparison view: the OBSERVED side is the verdict ────
    // What matters here is the traffic actually recorded, so the observed
    // badge comes first and carries the color; the policy badge is shown
    // only as the reference the traffic is checked against — always
    // neutral, never green, with a description written for this view
    // (the backend rationale is phrased for the policy on its own).
    const shelf = u.shelf_time_days || 0;
    const longLived = shelf >= QUANTUM_RISK_SHELF_THRESHOLD_DAYS;
    const expectedPosture = (data.expected || {}).pq_readiness || '—';
    const sessions = ['classical', 'hybrid', 'native']
      .map(k => [k, u[`observed_kex_sessions_${k}`] || 0]);
    const nSessions = sessions.reduce((s, [, n]) => s + n, 0);
    const breakdown = sessions.filter(([, n]) => n).map(([k, n]) => `${k} ${n}`).join(', ');
    const worst = u.observed_kex_posture_worst;

    // Observed verdict — four states, not a binary ok/warn:
    //   exposed      : long-lived data, worst observed KEX classical
    //   mitigated    : long-lived data, every observed KEX hybrid/native
    //                  (blue: acceptable, but the data IS long-lived)
    //   not priority : shelf time below the threshold (green)
    //   not evaluable: no observed session in the last ingest (grey)
    const oFlag = u.quantum_risk_observed_flag;
    const O = oFlag === true
      ? { cls: 'risk-warn', icon: 'ti-alert-triangle', title: 'exposed',
          text: `Data that must stay confidential for ${shelf} days is carried by at least one session with a classical key exchange: that traffic can be recorded today and decrypted later.` }
      : oFlag === false && longLived
      ? { cls: 'risk-medium', icon: 'ti-shield-half', title: 'mitigated',
          text: `Long-lived data (${shelf} days), but every observed session uses a post-quantum key exchange (worst: ${worst}). Recorded traffic stays protected against a future quantum adversary.` }
      : oFlag === false
      ? { cls: 'risk-ok', icon: 'ti-shield-check', title: 'not a priority',
          text: `Shelf time (${shelf} days) below the ${QUANTUM_RISK_SHELF_THRESHOLD_DAYS}-day alert threshold (worst observed key exchange: ${worst}).` }
      : { cls: 'risk-unknown', icon: 'ti-help-circle', title: 'not evaluable',
          text: 'No observed session was attributed to this use case in the last ingest.' };
    const observedBadge = `<div class="risk-badge ${O.cls}" style="margin-top:6px">
        <i class="ti ${O.icon}"></i>
        <div><strong>Quantum risk — observed traffic: ${O.title}</strong>${O.text}
        ${nSessions ? `<br><em>Key exchange over ${nSessions} observed session(s): ${breakdown}.</em>` : ''}</div>
      </div>`;

    // Policy reference — neutral whatever its flag: it states the target,
    // the verdict above says whether reality meets it.
    const eFlag = u.quantum_risk_expected_flag;
    const policyNote = eFlag === true
      ? `The policy itself accepts a classical key exchange for data kept confidential ${shelf} days: even full compliance would leave the traffic exposed.`
      : `The policy requires a '${expectedPosture}' key exchange for data kept confidential ${shelf} days. This is the target the observed traffic is checked against, not an assessment of it.`;
    const policyBadge = `<div class="risk-badge risk-reference" style="margin-top:6px">
        <i class="ti ti-file-description"></i>
        <div><strong>Quantum risk — policy (reference)</strong>${policyNote}</div>
      </div>`;

    const gLevel = u.governance_risk_level || "UNKNOWN";
    const G_CLS = { LOW: "risk-low", MEDIUM: "risk-medium", HIGH: "risk-high", CRITICAL: "risk-critical", UNKNOWN: "risk-unknown" };
    const G_ICON = { LOW: "ti-shield-check", MEDIUM: "ti-shield-half", HIGH: "ti-shield-exclamation", CRITICAL: "ti-alert-triangle", UNKNOWN: "ti-help-circle" };

    container.innerHTML = `
      <div class="cmp-persisted-label"><i class="ti ti-database"></i> State persisted on Neo4j (last save)</div>
      ${observedBadge}
      ${policyBadge}
      <div class="risk-badge ${G_CLS[gLevel] || 'risk-unknown'}" style="margin-top:6px">
        <i class="ti ${G_ICON[gLevel] || 'ti-help-circle'}"></i>
        <div><strong>Context risk: ${gLevel}</strong>${u.governance_risk_rationale || ''}</div>
      </div>`;
  } catch (e) {
    container.innerHTML = `<p class="cmp-persisted-empty">Persisted state not available: ${e.message}</p>`;
  }
}

const STATUS_ICON = { match: 'ti-circle-check', deviation: 'ti-alert-triangle', not_comparable: 'ti-help-circle' };
const STATUS_CLASS = { match: 'ok', deviation: 'warn', not_comparable: 'muted' };
const STATUS_LABEL = { match: 'Compliant', deviation: 'Deviation', not_comparable: 'Not comparable' };

function _cmpTableHtml(a) {
  const rows = a.parameters.map(p => {
    const isTierMatch = p.status === 'match' && p.exact_match === false;
    const cls   = isTierMatch ? 'oktier' : (STATUS_CLASS[p.status] || 'muted');
    const icon  = isTierMatch ? 'ti-arrow-up-circle' : (STATUS_ICON[p.status] || 'ti-help-circle');
    const label = isTierMatch ? 'Compliant (equivalent tier)' : (STATUS_LABEL[p.status] || p.status);
    const title = isTierMatch ? ` title="${p.detail.replace(/"/g, '&quot;')}"` : '';
    return `<tr class="cmp-row cmp-${cls}"${title}>
      <td>${p.scope_label}</td>
      <td>${p.label}</td>
      <td>${p.expected_value ?? '—'}</td>
      <td>${p.observed_value ?? '—'}</td>
      <td class="cmp-inequality">${p.inequality || '—'}</td>
      <td class="cmp-criterion" title="${(p.detail || '').replace(/"/g, '&quot;')}">${p.criterion_label || '—'}</td>
      <td><i class="ti ${icon}"></i> ${label}</td>
    </tr>`;
  }).join('');
  return `<table class="cmp-table">
    <thead><tr>
      <th>Scope</th><th>Parameter</th><th>Configured</th><th>Observed</th>
      <th>Relation</th><th>Evaluation criterion</th><th>Status</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderComparisonTable(assets) {
  const container = document.getElementById('comparison-content');
  if (!assets || assets.length === 0) {
    container.innerHTML = `
      <div class="finding-placeholder">
        <i class="ti ti-columns-3"></i>
        <p>No comparison available.</p>
        <p class="placeholder-sub">Requires a cbom.json ingest to have already run for this use case.</p>
      </div>`;
    return;
  }

  // ProxyJump SSH Bastion: at least one asset has ssh_context=2.
  // ssh_context=1 alone is not enough — it is written on all SSH records,
  // including standard use cases such as SFTP Backup.
  const isProxyJump = assets.some(a => a.ssh_context === 2);
  if (isProxyJump) {
    // ctx1: asset without ssh_context (bastion, ssh_context=1 not propagated)
    // ctx2: asset with ssh_context=2 (appserver, final hop)
    const ctx2 = assets.find(a => a.ssh_context === 2);
    const ctx1 = assets.find(a => a.ssh_context !== 2 && a.parameters && a.parameters.length > 0);
    let html = '';
    if (ctx1 && ctx1.parameters.length > 0) {
      html += `
        <div class="cmp-ctx-header cmp-ctx1">
          <i class="ti ti-terminal-2"></i>
          SSH #1 — clientext ↔ bastion
          <span>First hop: cryptographic negotiation with the jump server</span>
        </div>
        <div class="card" style="margin-top:0;border-top:none;border-radius:0 0 8px 8px">
          ${_cmpTableHtml(ctx1)}
        </div>`;
    }
    if (ctx2 && ctx2.parameters.length > 0) {
      html += `
        <div class="cmp-ctx-header cmp-ctx2" style="margin-top:18px">
          <i class="ti ti-terminal-2"></i>
          SSH #2 — clientext ↔ appserver
          <span>Second end-to-end hop: the bastion forwards opaque bytes, it takes no part in the cryptography</span>
        </div>
        <div class="card" style="margin-top:0;border-top:none;border-radius:0 0 8px 8px">
          ${_cmpTableHtml(ctx2)}
        </div>`;
    }
    container.innerHTML = html || '<p style="color:var(--text-tertiary);padding:20px">No data available.</p>';
    return;
  }

  // General case: ONE CARD PER ASSET WITH NON-EMPTY PARAMETERS, not only
  // the first. Before this fix only
  // `assets.find(a => a.parameters?.length > 0) || assets[0]` was shown —
  // correct for a single-session protocol where only one asset carries
  // real data (e.g. TLS with only the server declared), but a real defect
  // for any use case with SEVERAL assets EACH writing its own Observed —
  // always IPsec, since one profile is written per tunnel side (see
  // cbom_loader._hostnames_involved, which returns both involved
  // hostnames): the second asset (e.g. vpnremote, or mainfw in the road
  // warrior) was silently discarded, looking like "no data" when in fact
  // only one side had been picked arbitrarily and the other never shown.
  const withData = assets.filter(a => a.parameters && a.parameters.length > 0);
  if (withData.length === 0) {
    container.innerHTML = `
      <div class="finding-placeholder">
        <i class="ti ti-columns-3"></i>
        <p>No comparison available.</p>
        <p class="placeholder-sub">Requires a cbom.json ingest to have already run for this use case.</p>
      </div>`;
    return;
  }
  container.innerHTML = withData.map(a => `
    <div class="cmp-ctx-header" style="margin-top:12px">
      <i class="ti ti-server"></i>
      View from ${a.asset}
    </div>
    <div class="card" style="margin-top:0;border-top:none;border-radius:0 0 8px 8px">
      ${_cmpTableHtml(a)}
    </div>`).join('');
}

// ─── GUI INTERACTION ─────────────────────────────────────────────────────

function showUseCase(idx, el) {
  currentUC = idx;
  document.querySelectorAll('.nav-item').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  const uc = USE_CASES[idx];
  document.getElementById('uc-title').textContent = uc.name;
  document.getElementById('proto-label').textContent = uc.proto;
  document.getElementById('proto-label-top').textContent = uc.proto;
  renderParams(uc);
  renderGovernance(uc);
  renderTopologyAssets(uc);
  renderSessionDiagram(uc);
  renderFindingsPlaceholder();
  renderComparisonTable(null);
  const persistedBadges = document.getElementById('persisted-risk-badges');
  if (persistedBadges) persistedBadges.innerHTML = '';
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(uc);
}

function updateParam(key, val) {
  const uc = USE_CASES[currentUC];
  uc.selected[key] = val;
  // Realignment of parameters with dynamic options (a function, not a
  // static array): if the change just made has invalidated the currently
  // selected value of ANOTHER parameter (e.g. a TLS 1.3 cipher suite after
  // choosing "TLS 1.2 only"), reset it to the recommended value for the
  // new context — without this, the <select> would show a value now
  // inconsistent with the chosen protocol version, invisible until you
  // try to save.
  uc.params.forEach(p => {
    if (typeof p.options !== 'function') return;
    const validOptions = p.options(uc.selected);
    if (!validOptions.includes(uc.selected[p.key])) {
      uc.selected[p.key] = typeof p.recommended === 'function' ? p.recommended(uc.selected) : validOptions[0];
    }
  });
  renderParams(uc);
  // The PQC badge is derived from the key exchange parameter — it must
  // update whenever a parameter changes, not only the shelf time.
  renderGovernance(uc);
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(uc);
}

function updateParam2(key, val) {
  const uc = USE_CASES[currentUC];
  if (!uc.selected2) uc.selected2 = {};
  uc.selected2[key] = val;
  renderParams(uc);
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(uc);
}

function updateGovernance(key, val) {
  USE_CASES[currentUC].selectedGovernance[key] = val;
  renderGovernance(USE_CASES[currentUC]);
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(USE_CASES[currentUC]);
}

// Changes only the requested network parameter (hostname or IP): the zone
// and the association with the use case are not fields touched by this
// function, by construction — the topology structure stays unchanged.
function updateAsset(idx, field, val) {
  USE_CASES[currentUC].assets[idx][field] = val;
  renderSessionDiagram(USE_CASES[currentUC]);
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(USE_CASES[currentUC]);
}

function addAsset() {
  const name = prompt("Host name (e.g. 'newhost', no spaces):");
  if (!name) return;
  const zoneList = ZONE_KEYS.join(', ');
  let zone = (prompt(`Network zone (${zoneList}):`, 'internal_lan') || '').trim();
  if (!ZONE_KEYS.includes(zone)) zone = 'internal_lan';
  USE_CASES[currentUC].assets.push({
    name, role: "Manually configured asset", ip: "10.0.0.x", host: name, zone
  });
  renderTopologyAssets(USE_CASES[currentUC]);
  renderSessionDiagram(USE_CASES[currentUC]);
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(USE_CASES[currentUC]);
}

function removeAsset(idx) {
  USE_CASES[currentUC].assets.splice(idx, 1);
  renderTopologyAssets(USE_CASES[currentUC]);
  renderSessionDiagram(USE_CASES[currentUC]);
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(USE_CASES[currentUC]);
}

function resetToRecommended() {
  const uc = USE_CASES[currentUC];
  uc.params.forEach(p => {
    uc.selected[p.key] = typeof p.recommended === 'function' ? p.recommended(uc.selected) : p.recommended;
  });
  uc.governance.forEach(p => { uc.selectedGovernance[p.key] = p.recommended; });
  renderParams(uc);
  renderGovernance(uc);
  document.getElementById('cypher-output').innerHTML = generateCypherPreview(uc);
  showToast('Parameters reset to recommended values');
}

function loadMockFindings() {
  const uc = USE_CASES[currentUC];
  document.getElementById('findings-list').innerHTML = uc.demoFindings.map(f => `
    <div class="finding finding-${f.type}">
      <i class="ti ${f.icon} find-icon"></i>
      <div class="finding-text"><strong>${f.title}</strong><span>${f.desc}</span></div>
    </div>`).join('');
}

function switchTab(tab, el) {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  ['params', 'topology', 'comparison', 'findings', 'cypher'].forEach(t => {
    document.getElementById('tab-' + t).classList.toggle('hidden', t !== tab);
  });
}

function copyCypher() {
  navigator.clipboard.writeText(document.getElementById('cypher-output').innerText).catch(() => {});
  showToast('Cypher copied to clipboard');
}

function downloadCypher() {
  const uc = USE_CASES[currentUC];
  const text = document.getElementById('cypher-output').innerText;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${uc.id}.cypher`;
  a.click();
}

function exportAllCypher() {
  const all = USE_CASES.map(uc => generateCypherPreviewPlain(uc)).join('\n\n// ============================\n\n');
  document.getElementById('modal-cypher').innerHTML =
    USE_CASES.map(uc => generateCypherPreview(uc)).join('\n\n<span class="cmt">// ====================================</span>\n\n');
  document.getElementById('export-modal').classList.remove('hidden');
}

function generateCypherPreviewPlain(uc) {
  const tmp = document.createElement('div');
  tmp.innerHTML = generateCypherPreview(uc);
  return tmp.innerText;
}

function copyModalCypher() {
  navigator.clipboard.writeText(document.getElementById('modal-cypher').innerText).catch(() => {});
  showToast('Full script copied');
}

function downloadAllCypher() {
  const text = document.getElementById('modal-cypher').innerText;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'cbom_all_usecases.cypher';
  a.click();
}

function exportJSON() {
  const blob = new Blob([JSON.stringify(USE_CASES.map(buildUseCasePayload), null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'cbom_config.json';
  a.click();
}

function closeModal(e) {
  if (e.target.id === 'export-modal') {
    document.getElementById('export-modal').classList.add('hidden');
  }
}

function showToast(msg, isError = false) {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.background = isError ? '#A32D2D' : '';
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2800);
}

// ─── INIT ──────────────────────────────────────────────────────────────
// The sidebar (use-case list) is generated from USE_CASES, no longer
// hand-written in index.html — a use case added in data.js shows up here
// automatically, without touching two files kept aligned by hand (the
// drift between the two was exactly the problem to avoid: data.js listed
// nine, index.html showed seven, one of which had a name ("API Gateway
// mTLS") that no longer matched how the use case had since been corrected).

const PROTO_BADGE_LABEL = { ipsec: "IPsec", ssh: "SSH", tls: "TLS" };

function renderSidebarNav() {
  const nav = document.getElementById('nav-usecases');
  nav.innerHTML = USE_CASES.map((uc, idx) => {
    const badgeLabel = PROTO_BADGE_LABEL[uc.protoFamily] || uc.protoFamily.toUpperCase();
    return `
      <div class="nav-item" onclick="showUseCase(${idx},this)">
        <i class="ti ${uc.navIcon}"></i> ${uc.name}
        <span class="proto-badge badge-${uc.protoFamily}">${badgeLabel}</span>
      </div>`;
  }).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  renderSidebarNav();
  showUseCase(0, document.querySelector('.nav-item'));
});