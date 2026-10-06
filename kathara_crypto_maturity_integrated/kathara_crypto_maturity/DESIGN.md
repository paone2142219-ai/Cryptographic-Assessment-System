# Laboratorio Kathará — Stima della maturità crittografica

## 1. Dispositivi e ruoli

| Device       | Ruolo                                              | Rete/i                                    |
|--------------|-----------------------------------------------------|--------------------------------------------|
| clientext    | Client road-warrior (utente mobile esterno)         | netinternet                                |
| mainfw       | Firewall perimetrale + concentratore IPsec IKEv2    | netinternet, netfwdmz, netvpnlocal, netmgmt|
| dmzgw        | Gateway/router DMZ                                  | netfwdmz, netdmz                           |
| apigw        | API Gateway TLS 1.3 (dual-homed: DMZ + service mesh)| netdmz, netmesh                            |
| mailsrv      | Mail server (Postfix, STARTTLS)                     | netdmz                                     |
| ftpsrv       | SFTP server (chroot, DMZ)                           | netdmz                                     |
| vpnlocal     | Gateway IPsec site-to-site locale                   | netvpnlocal, nettunnel                     |
| vpnremote    | Gateway IPsec site-to-site remoto                   | nettunnel, netremote                       |
| remotehost   | Host rappresentativo della sede remota              | netremote                                  |
| bastion      | Bastion host SSH (unico ingresso amministrativo)    | netmgmt, netbstfw                          |
| internalgw   | Gateway/router LAN interna                          | netbstfw, netlan                           |
| appserver    | Application server                                  | netlan                                     |
| backupsrv    | Server di backup (destinazione SFTP)                | netlan                                     |
| logserver    | Syslog server cifrato (rsyslog + TLS)                | netlan                                     |
| svca, svcb   | Microservizi service mesh (gRPC + mTLS)             | netmesh                                    |

## 2. Collision domain (link Kathará) e subnet

| Collision domain | Subnet          | Membri                        | Fonte        |
|-------------------|-----------------|--------------------------------|--------------|
| netinternet        | 10.0.0.0/24     | clientext, mainfw              | diagramma    |
| netfwdmz           | 10.6.0.0/30     | mainfw, dmzgw                  | diagramma    |
| netvpnlocal        | 10.8.0.0/30     | mainfw, vpnlocal                | **assunto**  |
| nettunnel          | 10.5.0.0/30     | vpnlocal, vpnremote             | diagramma    |
| netremote          | 192.168.0.0/24  | vpnremote, remotehost           | subnet data, host **assunto** |
| netmgmt            | 10.3.0.0/30     | mainfw, bastion                 | diagramma    |
| netbstfw           | 10.7.0.0/30     | bastion, internalgw             | diagramma    |
| netdmz             | 10.1.0.0/24     | dmzgw, apigw, mailsrv, ftpsrv    | diagramma    |
| netmesh            | 10.4.0.0/24     | apigw, svca, svcb                | diagramma    |
| netlan             | 10.2.0.0/24     | internalgw, appserver, backupsrv, logserver | diagramma |

Pool IPsec road-warrior (assegnati dinamicamente da mainfw, non è un collision domain fisico):
- pool `employee`:  10.9.1.0/24
- pool `admin`:     10.9.2.0/24

## 3. I nove casi d'uso

1. VPN Road Warrior IPsec/IKEv2 (clientext ↔ mainfw), PSK, pool IP differenziati employee/admin, ACL su mainfw.
2. VPN Site-to-Site IPsec/IKEv2 (vpnlocal ↔ vpnremote), AES-GCM + PFS (esp_group), raccolta attiva via swanctl/VICI.
3. SSH bastion (accesso amministrativo centralizzato).
4. API Gateway TLS 1.3 (apigw, nginx).
5. Service mesh mTLS su gRPC (svca ↔ svcb).
6. SMTP/STARTTLS (appserver → mailsrv).
7. SFTP DMZ (clientext ↔ ftpsrv).
8. Backup schedulato SFTP (appserver → backupsrv).
9. Syslog cifrato TLS (tutti gli host → logserver) — caso mancante, aggiunto qui.

## 4. Architettura di raccolta metadati (distribuita, passiva + attiva)

**Nota di scope**: in questa fase del lavoro la raccolta si ferma deliberatamente al
dato grezzo. Non esiste (ancora) alcuna elaborazione, normalizzazione o aggregazione:
l'obiettivo attuale è consolidare l'infrastruttura di rete e il paradigma distribuito
di raccolta; l'eventuale fase di analisi/trasformazione dei dati raccolti è un problema
volutamente disaccoppiato, da affrontare separatamente in un secondo momento.

Sensori PASSIVI (Zeek), un solo processo per interfaccia (Zeek non supporta più interfacce
nella stessa invocazione dalla serie 2.2/3.x in poi). La copertura segue un principio di
"ultimo miglio": si cattura una sola volta, il più vicino possibile alla destinazione finale,
non a ogni hop intermedio — confermato anche empiricamente: una versione precedente catturava
la stessa sessione fino a cinque volte lungo il suo percorso (es. appserver→mailsrv vista da
internalgw, bastion due volte, mainfw e dmzgw), duplicazione eliminata deliberatamente:
  - **dmzgw**   (eth1 netdmz): ultimo hop prima di qualunque host DMZ — vede TLS apigw,
    STARTTLS verso mailsrv, SFTP/SSH verso ftpsrv, indipendentemente dall'origine del
    traffico (road warrior, LAN interna, o altro).
  - **internalgw** (eth1 netlan): ultimo hop prima di qualunque host della LAN interna —
    vede SSH backup verso backupsrv **e syslog TLS verso logserver** (logserver non ha
    un sensore proprio: sta sulla stessa netlan, "ultimo miglio" lo copre già).
  - **bastion** (eth0 netmgmt): unico punto da cui le sessioni SSH dirette a bastion stesso
    sono osservabili. Niente sensore su eth1 (netbstfw): il traffico di puro transito
    LAN↔DMZ che attraversa bastion è già coperto una volta sola da internalgw/dmzgw.
  - **mainfw** (eth0 netinternet): unico punto dove IKE_SA_INIT del road warrior è
    osservabile in chiaro, prima che il tunnel lo cifri. Niente sensore su eth1
    (netfwdmz): il traffico decifrato che vi transita, diretto alla DMZ, è già coperto
    una volta sola da dmzgw.
  - **vpnlocal** (eth1 nettunnel) / **vpnremote** (eth0 nettunnel): stessa logica, per
    IKE_SA_INIT del tunnel site-to-site.
  - **svca** (eth0 netmesh): **eccezione al principio di "ultimo miglio"**. netmesh è
    una rete switchata su cui svca e svcb si parlano direttamente, senza passare da un
    gateway di rete intermedio: un terzo host non coinvolto non vedrebbe nulla di quel
    traffico. L'unico vantage point possibile per il loop Ping svca↔svcb resta uno dei
    due endpoint stessi; svca è stato scelto arbitrariamente (uno solo, mai anche svcb,
    altrimenti si reintroduce esattamente la duplicazione eliminata altrove — vedendo
    il proprio traffico locale, un host cattura comunque l'intera sessione
    bidirezionale). Nota: apigw è sì collegato a netmesh (10.4.0.1) e da questa
    revisione del laboratorio è anche un client mTLS applicativo del mesh (bridge
    `/api/mesh/*` → gRPC Hello/Chain su svca, vedi README.md, caso d'uso 9), ma questo
    non contraddice l'eccezione sopra: apigw è un endpoint della propria chiamata (la
    vede per definizione, come qualunque client), non un terzo host che intercetta
    passivamente traffico altrui — il traffico *tra* svca e svcb resta osservabile solo
    da uno dei due, esattamente come descritto.

Sensore ATTIVO (VICI/swanctl), non di rete ma di endpoint, per il gap di osservabilità IPsec
già discusso (IKE_AUTH cifrato ⇒ Child SA non osservabile passivamente):
  - **mainfw**, **vpnlocal**, **vpnremote** eseguono ciascuno lo script `vici_collector.sh`
    che interroga periodicamente `swanctl --list-sas` in locale e scrive l'output testuale
    grezzo in `/shared/<hostname>/ipsec_status.txt`.

Tutti gli host montano la cartella condivisa Kathará `/shared`, organizzata per hostname
(per i sensori multi-interfaccia, per hostname-interfaccia, es. `mainfw-eth0`):
`/shared/<hostname[-ethN]>/zeeklogs/*.log` e, dove applicabile, `/shared/<hostname>/ipsec_status.txt`.
Non c'è alcun nodo designato a raccogliere/fondere questi dati: ciascun sensore scrive
esclusivamente nel proprio sottoalbero, e i dati restano lì, separati per host e per sensore,
a disposizione di qualunque elaborazione futura si decida di costruire sopra.

**Segmento senza copertura, deliberatamente**: netremote (192.168.0.0/24, remotehost).
Non è un gap dimenticato: remotehost non esegue alcun servizio applicativo TLS/SSH/IPsec
osservabile nei casi d'uso attuali (solo traffico ICMP di test); tutto il traffico
rilevante verso quella rete attraversa il tunnel site-to-site cifrato, la cui unica
fonte di osservazione possibile è già coperta dal collector attivo su vpnlocal/vpnremote,
non da un sensore di rete aggiuntivo su quel segmento.
