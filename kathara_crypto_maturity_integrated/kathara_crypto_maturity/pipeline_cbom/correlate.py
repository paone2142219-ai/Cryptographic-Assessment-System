# -*- coding: utf-8 -*-
"""
correlate.py — fusione di fonti ETEROGENEE che descrivono lo stesso
evento da angolazioni diverse. Non è deduplicazione: qui i record di
partenza non sono ridondanti, sono complementari, e la fusione arricchisce
un record invece di scartarne uno.

Due correlazioni implementate:
  1. TLS <-> x509, via cert_chain_fps.
  2. TLS <-> SMTP, via uid (stessa connessione, due analizzatori Zeek
     diversi sullo stesso traffico).
"""
from __future__ import annotations


def correlate_tls_with_certs(tls_records: list[dict], cert_index: dict[str, dict]) -> int:
    """Arricchisce in-place i record TLS con il certificato corrispondente.
    Restituisce il numero di correlazioni riuscite."""
    correlated = 0
    for rec in tls_records:
        fps = rec.get("cert_chain_fps") or []
        if not fps:
            continue
        leaf_fp = fps[0]
        cert = cert_index.get(leaf_fp)
        if cert is None:
            continue

        rec["certificate"] = {
            "fingerprint": cert["fingerprint"],
            "subject": cert["subject"],
            "issuer": cert["issuer"],
            "key_type": cert["key_type"],
            "key_length": cert["key_length"],
            "curve": cert.get("curve"),
            "sig_alg": cert["sig_alg"],
            "not_valid_after": cert["not_valid_after"],
            "observed_by": cert["observed_by"],
        }
        # La dimensione HOSTKEY del record TLS era UNKNOWN perché il solo
        # ssl.log non porta il dettaglio della chiave — ora che il
        # certificato è correlato, si eredita la sua valutazione.
        if "pqc_assessment" in rec and "pqc_assessment" in cert:
            rec["pqc_assessment"]["HOSTKEY"] = cert["pqc_assessment"]["HOSTKEY"]
        correlated += 1
    return correlated


def correlate_smtp_with_tls(smtp_records: list[dict], tls_records: list[dict]) -> int:
    """Arricchisce in-place i record TLS con il contesto SMTP dello stesso
    UID Zeek (stessa connessione, due analizzatori diversi sullo stesso
    traffico). Segnala esplicitamente se le due fonti sono in disaccordo
    invece di far vincere una delle due in silenzio.

    Restituisce il numero di correlazioni riuscite."""
    smtp_by_uid = {r["uid"]: r for r in smtp_records if r.get("uid")}
    correlated = 0

    for rec in tls_records:
        uid = rec.get("uid")
        if not uid or uid not in smtp_by_uid:
            continue
        smtp = smtp_by_uid[uid]

        rec["application_protocol"] = "SMTP"
        rec["smtp_context"] = {
            "helo": smtp.get("helo"),
            "last_reply": smtp.get("last_reply"),
            "starttls_confirmed_by_smtp_log": smtp.get("starttls_confirmed"),
        }
        # Due fonti indipendenti (l'analizzatore SMTP e l'analizzatore TLS
        # di Zeek) dovrebbero concordare sul fatto che la sessione sia
        # passata a TLS. Se non concordano, è un'anomalia da segnalare,
        # non da appiattire scegliendo quale fonte credere.
        rec["smtp_tls_consistency"] = (
            "consistent" if smtp.get("starttls_confirmed") and rec.get("established")
            else "MISMATCH_investigate"
        )
        correlated += 1

    return correlated


def correlate_ssh_proxyjump(ssh_records: list[dict], inventory: dict[str, str]) -> int:
    """Identifica e annota le sessioni SSH che appartengono a un ProxyJump.

    Problema epistemologico: Zeek vede due connessioni TCP distinte —
      conn 1:  clientext:PORT → bastion:22        (SSH #1)
      conn 2:  bastion:PORT   → appserver:22      (SSH #2)
    La connessione 2 ha src_ip = bastion. Senza questo correlatore,
    cbom_loader attribuisce entrambe al caso d'uso "SSH Bastion Access"
    ma con lo stesso hostname-key (bastion per #1, appserver per #2),
    perdendo la distinzione tra i due contesti crittografici.

    Strategia di attribuzione — puramente topologica, senza IP hardcoded:
    un record SSH ha ssh_context = 2 se E SOLO SE:
      - il suo src_hostname (dall'inventario) è "bastion" (o più in
        generale: è un host dichiarato come jump server nell'inventario,
        riconoscibile dal nome canonico)
      - il suo dst_hostname (dall'inventario) è un host interno
        (non coincide con src_hostname)
    Tutti gli altri record SSH restano ssh_context = 1 (default).

    Il campo ssh_context viene poi letto da cbom_loader per costruire
    observed_key con suffisso ::ctx1 o ::ctx2, permettendo al drift_engine
    di confrontare Expected e Observed per contesto distinto.

    Restituisce il numero di record annotati come ctx2.
    """
    # Costruisce la mappa inversa hostname -> ip dall'inventario
    hostname_to_ip = {v: k for k, v in inventory.items()}

    # Hostname canonici dei jump server: qualsiasi host il cui nome
    # contiene "bastion" o "jump" (euristica stabile per la topologia
    # Kathará dichiarata — mai inferita dal traffico).
    jump_hostnames = {
        h for h in hostname_to_ip
        if "bastion" in h.lower() or "jump" in h.lower()
    }

    ctx2_count = 0
    for rec in ssh_records:
        hint = rec.get("asset_hint") or {}
        src_host = hint.get("src_hostname")
        dst_host = hint.get("dst_hostname")

        # ssh_context = 2: sorgente è un jump server, destinazione è
        # un host diverso (la sessione è forwarded attraverso il bastion)
        if src_host and src_host in jump_hostnames and dst_host and dst_host != src_host:
            rec["ssh_context"] = 2
            ctx2_count += 1
        else:
            # Contesto 1 esplicito (default): clientext → bastion, o
            # qualsiasi altra sessione SSH non riconosciuta come ProxyJump.
            rec["ssh_context"] = 1

    return ctx2_count