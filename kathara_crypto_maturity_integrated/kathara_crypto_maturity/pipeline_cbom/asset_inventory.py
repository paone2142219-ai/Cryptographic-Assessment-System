# -*- coding: utf-8 -*-
"""
asset_inventory.py — mappa IP -> hostname, per rendere leggibile la CBOM
senza fare quello che la pipeline non deve fare.

Confine deliberato, da non spostare in futuro senza motivarlo di nuovo:
questo modulo assegna un NOME a un indirizzo ("10.1.0.10 è apigw"), non un
RUOLO applicativo né un CASO D'USO ("questa connessione è il caso d'uso
API Gateway"). Sono affermazioni epistemicamente diverse — un hostname è
un fatto stabile, un caso d'uso è un'interpretazione che dipende da una
policy attesa non ancora presente in questa fase del progetto (vive nella
componente UseCase/Policy dell'ontologia, deliberatamente disaccoppiata
per ora — vedi la discussione precedente).

L'inventario è un file di configurazione ESTERNO, mantenuto a mano, mai
derivato dal traffico osservato. Se il file manca, la pipeline funziona
comunque, semplicemente senza l'arricchimento — non è mai un requisito.

Ogni annotazione porta esplicitamente "_source": "external_static_
inventory", per non lasciare ambiguità su cosa sia stato osservato sul
filo e cosa sia stato dichiarato a parte.
"""
from __future__ import annotations
import json
from pathlib import Path

SOURCE_LABEL = "external_static_inventory"


def load(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def _hint_for(ip: str | None, inventory: dict[str, str]) -> str | None:
    if not ip:
        return None
    return inventory.get(ip)


def annotate(records: list[dict], inventory: dict[str, str]) -> int:
    """Aggiunge, dove possibile, un campo 'asset_hint' — mai sovrascrive
    campi osservati, si limita ad aggiungere un'etichetta esplicitamente
    marcata come proveniente da configurazione esterna.
    Restituisce il numero di record annotati."""
    if not inventory:
        return 0

    annotated = 0
    for rec in records:
        hint: dict[str, str] = {}

        # TLS / SSH: src_ip, dst_ip
        src = _hint_for(rec.get("src_ip"), inventory)
        dst = _hint_for(rec.get("dst_ip"), inventory)
        # IPsec IKE: local_addr, remote_addr
        local = _hint_for(rec.get("local_addr"), inventory)
        remote = _hint_for(rec.get("remote_addr"), inventory)

        if src:
            hint["src_hostname"] = src
        if dst:
            hint["dst_hostname"] = dst
        if local:
            hint["local_hostname"] = local
        if remote:
            hint["remote_hostname"] = remote

        if hint:
            hint["_source"] = SOURCE_LABEL
            rec["asset_hint"] = hint
            annotated += 1

    return annotated
