# -*- coding: utf-8 -*-
"""
ipsec_parser.py — reads shared/<sensor>/ipsec_status.txt: raw text
produced by `swanctl --list-sas` (not JSON, even though it is written by
an active collector — see vici_collector.sh).

Regexes validated against the real output of a running charon daemon and
against independent (not self-produced) examples while developing the
lab — see earlier sessions for the details of the verification.

IKE/ESP distinction: the Child SA (data plane) carries a DH group only
if the rekey actually included it in the proposal — the very first
Child SA negotiated inside IKE_AUTH never carries one by construction of
the IKEv2 protocol, regardless of how the proposal is configured.
has_pfs therefore reflects what was observed in THIS sample, not what
the configuration would allow in the abstract.
"""
from __future__ import annotations
import re
from pathlib import Path

_IKE_HEADER_RE = re.compile(
    r"^(?P<name>[\w.\-]+):\s+#(?P<uid>\d+),\s+(?P<state>[A-Z]+),\s+IKEv2"
)
_LOCAL_RE = re.compile(r"^\s*local\s+'(?P<id>[^']+)'\s+@\s+(?P<addr>[0-9.]+)\[")
_REMOTE_RE = re.compile(r"^\s*remote\s+'(?P<id>[^']+)'\s+@\s+(?P<addr>[0-9.]+)\[")
# The trailing (/KEn_<name>)* group captures the RFC 9370 additional key
# exchanges strongSwan prints after the IKE_SA_INIT group when a hybrid
# post-quantum proposal is negotiated (e.g. ".../ECP_384/KE1_ML_KEM_768").
# Without it, the "$" anchor made the whole proposal line fail to match for
# any hybrid IKE SA — its cipher, PRF and group were silently lost.
_IKE_PROPOSAL_RE = re.compile(
    r"^\s*(?P<enc>[A-Z0-9_]+)-(?P<enc_bits>\d+)/PRF_(?P<prf>[A-Z0-9_]+)/(?P<group>[A-Z0-9_]+)"
    r"(?P<additional>(?:/KE\d+_[A-Z0-9_]+)*)\s*$"
)
_ADDITIONAL_KE_RE = re.compile(r"/KE\d+_([A-Z0-9_]+)")
_CHILD_HEADER_RE = re.compile(
    r"^\s*(?P<name>[\w.\-]+):\s+#(?P<cuid>\d+),\s+reqid\s+\d+,\s+(?P<state>[A-Z]+),\s+"
    r"TUNNEL,\s+ESP:(?P<enc>[A-Z0-9_]+)-(?P<enc_bits>\d+)(?:/(?P<group>[A-Z0-9_]+))?"
)

# ── swanctl --list-conns: CONFIGURATION metadata, not state ───────────────
# A different source from --list-sas: this is where the authentication
# method and the configured rekey time live, never observable in the
# output of the active SAs. It never contains the PSK secret itself
# (swanctl does not expose it, here or elsewhere) — only that the
# authentication is "pre-shared key", not its value.
_CONN_HEADER_RE = re.compile(
    r"^(?P<name>[\w.\-]+):\s+IKEv\d,\s+(?P<reauth>[^,]+),\s+rekeying every (?P<rekey>\d+)s"
)
_AUTH_LINE_RE = re.compile(
    r"^\s*(?P<side>local|remote)\s+(?P<method>pre-shared key|public key|EAP[\w_]*)\s+authentication:"
)
_CHILD_CONN_RE = re.compile(
    r"^\s*(?P<name>[\w.\-]+):\s+TUNNEL,\s+rekeying every (?P<rekey>\d+)s"
)

_AUTH_METHOD_MAP = {
    "pre-shared key": "psk",
    "public key": "pubkey",
}


def parse_conns(path: Path, sensor_id: str) -> dict[str, dict]:
    """Reads the output of `swanctl --list-conns` (raw text, same
    principle as --list-sas). Returns {connection_name: metadata},
    indexed by name — it is meant to be correlated with the records
    produced by parse(), not to be used on its own."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return {}

    conns: dict[str, dict] = {}
    current_name: str | None = None
    pending_side: str | None = None

    for line in text.splitlines():
        m = _CONN_HEADER_RE.match(line)
        if m:
            current_name = m.group("name")
            conns[current_name] = {
                "conn_name": current_name,
                "sensor_id": sensor_id,
                "reauthentication": m.group("reauth").strip(),
                "ike_rekey_time_seconds": int(m.group("rekey")),
                "local_auth_method": None,
                "remote_auth_method": None,
                "child_rekey_time_seconds": None,
            }
            pending_side = None
            continue
        if current_name is None:
            continue

        m = _AUTH_LINE_RE.match(line)
        if m:
            method = _AUTH_METHOD_MAP.get(m.group("method"), m.group("method").lower())
            conns[current_name][f'{m.group("side")}_auth_method'] = method
            continue

        m = _CHILD_CONN_RE.match(line)
        if m:
            conns[current_name]["child_rekey_time_seconds"] = int(m.group("rekey"))
            continue

    return conns


def merge_conn_metadata(sa_records: list[dict], conn_metadata: dict[str, dict]) -> int:
    """Enriches the IKE records (from --list-sas) in place with the
    configuration metadata found in --list-conns for the same connection
    name. Not every SA has a matching connection in the --list-conns
    sample of the same sensor (e.g. different sensors collecting at
    different times) — in that case the fields stay explicitly None,
    never guessed. Returns the number of enriched records."""
    merged = 0
    for rec in sa_records:
        meta = conn_metadata.get(rec.get("conn_name"))
        rec["auth_method"] = {
            "local": meta["local_auth_method"] if meta else None,
            "remote": meta["remote_auth_method"] if meta else None,
        }
        rec["ike_rekey_time_seconds"] = meta["ike_rekey_time_seconds"] if meta else None
        rec["child_rekey_time_seconds"] = meta["child_rekey_time_seconds"] if meta else None
        if meta:
            merged += 1
    return merged


def _finalize(rec: dict) -> dict:
    """Computes data_plane_pfs_observed when an IKE block is closed, once
    all its Child SAs are known. Three possible outcomes, never flattened
    into a boolean that would hide the third case:
      - True  : at least one Child SA has PFS observed in this sample
      - False : there are Child SAs, none with PFS observed right now
      - None  : no Child SA known for this IKE SA in this sample
                (not "PFS absent", literally "unknown, no data")"""
    child_sas = rec.get("child_sas") or []
    if not child_sas:
        rec["data_plane_pfs_observed"] = None
    else:
        rec["data_plane_pfs_observed"] = any(c.get("has_pfs") for c in child_sas)
    return rec


def parse(path: Path, sensor_id: str) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return []

    lines = text.splitlines()
    records: list[dict] = []
    current: dict | None = None

    for line in lines:
        m = _IKE_HEADER_RE.match(line)
        if m:
            if current:
                records.append(_finalize(current))
            current = {
                "protocol": "IPSEC_IKE",
                "sensor_id": sensor_id,
                "conn_name": m.group("name"),
                "ike_uid": m.group("uid"),
                "state": m.group("state"),
                # Placeholders: filled in later by merge_conn_metadata(),
                # but declared here so that THEIR POSITION in the JSON is
                # next to the connection's identity, not at the end of the
                # dictionary (where a key added later would end up).
                "auth_method": {"local": None, "remote": None},
                "ike_rekey_time_seconds": None,
                "child_rekey_time_seconds": None,
                # Readability summary: "was PFS observed on at least one
                # Child SA of this IKE SA in THIS sample?" — computed at
                # the end of parsing, not inferred from the config. The
                # full per-Child-SA detail still remains in
                # child_sas[].has_pfs — this is only the quick view.
                "data_plane_pfs_observed": None,
                "local_id": None, "local_addr": None,
                "remote_id": None, "remote_addr": None,
                "ike_enc": None, "ike_enc_bits": None,
                "ike_prf": None, "ike_group": None,
                # RFC 9370 additional key exchanges, in negotiation order
                # (empty for a purely classical IKE SA).
                "ike_additional_ke": [],
                "child_sas": [],
            }
            continue
        if current is None:
            continue

        m = _LOCAL_RE.match(line)
        if m:
            current["local_id"] = m.group("id")
            current["local_addr"] = m.group("addr")
            continue

        m = _REMOTE_RE.match(line)
        if m:
            current["remote_id"] = m.group("id")
            current["remote_addr"] = m.group("addr")
            continue

        m = _IKE_PROPOSAL_RE.match(line)
        if m:
            current["ike_enc"] = m.group("enc")
            current["ike_enc_bits"] = int(m.group("enc_bits"))
            current["ike_prf"] = m.group("prf")
            current["ike_group"] = m.group("group")
            current["ike_additional_ke"] = _ADDITIONAL_KE_RE.findall(m.group("additional") or "")
            continue

        m = _CHILD_HEADER_RE.match(line)
        if m:
            group = m.group("group")
            current["child_sas"].append({
                "protocol": "IPSEC_ESP",
                "child_name": m.group("name"),
                "child_uid": m.group("cuid"),
                "state": m.group("state"),
                "esp_enc": m.group("enc"),
                "esp_enc_bits": int(m.group("enc_bits")),
                "esp_group": group,
                # has_pfs=True ONLY if this specific sample observed a DH
                # group in the Child SA — not an inference from the
                # configuration.
                "has_pfs": group is not None,
            })
            continue

    if current:
        records.append(_finalize(current))

    return records


# ── swanctl_config.txt: declared STATIC configuration ─────────────────────
# A third source, different from the first two: it does not query VICI, it
# is a raw copy of the /etc/swanctl/conf.d/*.conf files exactly as they are
# written. This is where the full ESP/IKE proposal as declared lives (e.g.
# "aes256gcm16-ecp384"), never visible in either --list-sas or
# --list-conns — needed to make the declared/observed comparison on PFS
# explicit, instead of leaving it implicit and requiring it to be known
# by heart.
_BLOCK_OPEN_RE = re.compile(r"^\s*([\w.\-]+)\s*\{\s*(?:#.*)?$")
_BLOCK_CLOSE_RE = re.compile(r"^\s*\}\s*$")
_IKE_PROPOSALS_LINE_RE = re.compile(r"^\s*proposals\s*=\s*(\S+)")
_ESP_PROPOSALS_LINE_RE = re.compile(r"^\s*esp_proposals\s*=\s*(\S+)")

# Normalizes the DH/curve token of the swanctl.conf syntax (lowercase,
# e.g. "ecp384") to the same form used by the rest of the
# parser/normalizer (uppercase, e.g. "ECP_384", the one appearing in
# --list-sas) — the same entity, two different syntaxes depending on the
# source.
_DH_TOKEN_NORMALIZE = {
    "ecp256": "ECP_256", "ecp384": "ECP_384", "ecp521": "ECP_521",
    "curve25519": "X25519", "x25519": "X25519",
    "modp1024": "MODP_1024", "modp1536": "MODP_1536",
    "modp2048": "MODP_2048", "modp3072": "MODP_3072", "modp4096": "MODP_4096",
}


def _declared_dh_group(proposal_str: str) -> str | None:
    """Extracts the DH group/curve from a swanctl.conf proposal string
    (e.g. 'aes256gcm16-ecp384' -> 'ECP_384'). Returns None if no component
    of the proposal matches a known group — e.g. a proposal such as
    'aes256gcm16' alone, with no DH group given, which is itself a piece
    of information (no PFS possible on that Child SA, for any rekey)."""
    for token in proposal_str.lower().split("-"):
        if token in _DH_TOKEN_NORMALIZE:
            return _DH_TOKEN_NORMALIZE[token]
    return None


def parse_static_config(path: Path, sensor_id: str) -> dict[str, dict]:
    """Reads the raw copy of /etc/swanctl/conf.d/*.conf and returns
    {connection_name: {"declared_ike_proposal":..., "children": {child_name: {...}}}}.

    Stack-based parser over the nested block structure of swanctl.conf —
    not a generic parser of the format (which admits much more syntax than
    the lab uses), only what is needed to extract
    connections{name{...children{name{...esp_proposals=...}}}}."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return {}

    stack: list[str] = []
    result: dict[str, dict] = {}

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0]  # full-line or trailing comments
        if not line.strip():
            continue

        m = _BLOCK_CLOSE_RE.match(line)
        if m:
            if stack:
                stack.pop()
            continue

        m = _BLOCK_OPEN_RE.match(line)
        if m:
            stack.append(m.group(1))
            continue

        # connections { <conn_name> { proposals = ... } }
        if len(stack) == 2 and stack[0] == "connections":
            m = _IKE_PROPOSALS_LINE_RE.match(line)
            if m:
                conn_name = stack[1]
                result.setdefault(conn_name, {"declared_ike_proposal": None, "children": {}})
                result[conn_name]["declared_ike_proposal"] = m.group(1)
            continue

        # connections { <conn_name> { children { <child_name> { esp_proposals = ... } } } }
        if len(stack) == 4 and stack[0] == "connections" and stack[2] == "children":
            m = _ESP_PROPOSALS_LINE_RE.match(line)
            if m:
                conn_name, child_name = stack[1], stack[3]
                result.setdefault(conn_name, {"declared_ike_proposal": None, "children": {}})
                result[conn_name]["children"].setdefault(child_name, {})
                result[conn_name]["children"][child_name]["declared_esp_proposal"] = m.group(1)

    return result


def merge_static_config(sa_records: list[dict], static_config: dict[str, dict]) -> int:
    """Enriches the IKE records (and their Child SAs) in place with the
    proposal declared in the static configuration. As for
    merge_conn_metadata: if there is no match, the fields stay explicitly
    None, never guessed. Returns the number of enriched IKE records (it
    does not count the individual Child SAs)."""
    merged = 0
    for rec in sa_records:
        conf = static_config.get(rec.get("conn_name"))
        rec["declared_ike_proposal"] = conf["declared_ike_proposal"] if conf else None

        for child in rec.get("child_sas", []):
            child_conf = (conf or {}).get("children", {}).get(child.get("child_name"))
            declared = child_conf["declared_esp_proposal"] if child_conf else None
            child["declared_esp_proposal"] = declared
            child["declared_dh_group"] = _declared_dh_group(declared) if declared else None
            # Explicitly distinct from has_pfs (observed): this says
            # whether the CONFIGURATION would allow PFS on a rekey, not
            # whether it was ever observed. The two fields must be read
            # together, never one in place of the other.
            child["declared_pfs_capable"] = child["declared_dh_group"] is not None

        if conf:
            merged += 1
    return merged
