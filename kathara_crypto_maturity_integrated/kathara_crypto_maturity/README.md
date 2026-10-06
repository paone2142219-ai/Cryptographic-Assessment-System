# Laboratorio Kathará — Stima della maturità crittografica

Vedi `DESIGN.md` per il piano di indirizzamento completo e le assunzioni fatte
sui due segmenti non esplicitamente indirizzati nel disegno originale
(`mainfw↔vpnlocal`, indirizzo di `vpnremote` verso la sede remota).

## Avvio

```bash
./deploy.sh
```

Equivalente, passo per passo:

```bash
./gen_pki.sh        # genera CA di laboratorio + certificati leaf
./build_images.sh   # costruisce le 10 immagini Docker custom (images/Dockerfile.*)
kathara lstart       # avvia i 16 dispositivi
```

`gen_pki.sh` e `build_images.sh` vanno eseguiti una sola volta (o dopo aver
modificato PKI/Dockerfile). `kathara lstart` può essere ripetuto liberamente.

## Verifica rapida che tutto sia in piedi

```bash
kathara connect bastion
ls /shared/                        # un sottoalbero per hostname sensore
find /shared -name "*.log" -o -name "ipsec_status.txt"
```

## Test manuali per caso d'uso

**1. VPN Road Warrior (clientext ↔ mainfw)**
```bash
kathara connect clientext
swanctl --initiate --child rw-employee-child   # identità employee -> pool 10.9.1.0/24
# oppure:
swanctl --initiate --child rw-admin-child       # identità admin    -> pool 10.9.2.0/24
swanctl --list-sas
ping 10.1.0.10   # DMZ: raggiungibile da entrambi i profili
ping 10.3.0.2    # bastion: raggiungibile solo dal profilo admin
```

**2. VPN Site-to-Site (vpnlocal ↔ vpnremote)** — si avvia da sola
(`start_action = start` su vpnlocal). Verifica:
```bash
kathara connect vpnlocal
swanctl --list-sas
cat /shared/vpnlocal/ipsec_status.txt   # raccolta attiva VICI
```

**3. Accesso amministrativo SSH (bastion, e da lì ad appserver)**
```bash
kathara connect clientext
swanctl --initiate --child rw-admin-child
ssh -i /root/.ssh/bob_admin_ed25519 admin@10.3.0.2
```
Per il secondo salto verso `appserver`, non usare `-J` sulla riga di
comando (l'identità non viene ereditata in modo affidabile dal primo
salto) — usa invece `~/.ssh/config` su `clientext` (dettagli e comandi
completi in `TUTORIAL.md`, sezione 7.3):
```bash
ssh appserver-jump   # richiede gli host bastion-jump/appserver-jump già in ~/.ssh/config
```

**4. API Gateway TLS 1.3 (apigw)**
```bash
kathara connect clientext   # o qualunque host con rotta verso 10.1.0.10
curl -v --tlsv1.3 --cacert /etc/pki/ca.pem https://10.1.0.10/api/health
curl -v --tls-max 1.2 --cacert /etc/pki/ca.pem https://10.1.0.10/   # deve FALLIRE: solo TLS 1.3
```

**5. Service mesh mTLS/gRPC (svca ↔ svcb)** — traffico generato
automaticamente dal loop nei rispettivi `.startup`. Verifica:
```bash
kathara connect svca
tail -f /var/log/mesh_node.log
```

**6. SMTP/STARTTLS (appserver → mailsrv)**
```bash
kathara connect appserver
/opt/mailtest/send_test_mail.sh
```

**7. SFTP DMZ (clientext ↔ ftpsrv)**
```bash
kathara connect clientext
sftp -i /root/.ssh/id_ed25519 sftpuser@10.1.0.12
sftp> cd upload
sftp> put /etc/hostname
```

**8. Backup schedulato (appserver → backupsrv)**
```bash
kathara connect appserver
/opt/backup/run_backup.sh   # esecuzione manuale immediata (il cron gira alle 02:30)
```

**9. API Gateway → Service Mesh (clientext → apigw → svca → svcb, end-to-end)**

Dalla versione integrata del laboratorio, `apigw` non è più un semplice
"vetrina" TLS 1.3 scollegata dal mesh: espone anche un bridge HTTP→gRPC/mTLS
(`/opt/gw/grpc_proxy.py`, in ascolto in locale su `127.0.0.1:8080`, invocato
da nginx in `location /api/mesh/`) che lo rende un vero e proprio client
mTLS del service mesh, con la propria identità (`/etc/pki/cert.pem`, lo
stesso certificato già usato per il TLS server — emesso con
`extendedKeyUsage=serverAuth,clientAuth`, vedi `gen_pki.sh`).

```bash
kathara connect clientext
swanctl --initiate --child rw-employee-child   # o rw-admin-child, indifferente: la DMZ è raggiungibile da entrambi

# apigw chiama Hello su svca via mTLS gRPC
curl -sk --cacert /etc/pki/ca.pem https://10.1.0.10/api/mesh/hello

# apigw chiama Chain su svca, che a sua volta inoltra una Hello a svcb via mTLS
curl -sk --cacert /etc/pki/ca.pem https://10.1.0.10/api/mesh/chain
```

La seconda chiamata attraversa **tre hop cifrati indipendenti**, ciascuno
con la propria autenticazione reciproca a certificato:

```
clientext --[IPsec road warrior]--> mainfw --[DMZ]--> apigw
                                                          │
                                                    HTTPS TLS 1.3 (termina qui)
                                                          │
                                                 grpc_proxy.py (127.0.0.1:8080)
                                                          │
                                                  gRPC/mTLS (apigw è client)
                                                          ▼
                                                        svca
                                                          │
                                                  gRPC/mTLS (svca è client)
                                                          ▼
                                                        svcb
```

`svca`/`svcb` restituiscono anche il CN del certificato del chiamante
(`tls_peer`, estratto da `mesh_node.py` con `context.auth_context()`), utile
per verificare a occhio che l'autenticazione mTLS sia realmente avvenuta a
ogni hop e non solo lato server:

```json
{
  "path": "apigw -> svca -> svcb",
  "hops": [
    {"node": "svca", "message": "svca ha ricevuto la chain", "tls_peer": "apigw.katharalab.local"},
    {"node": "svcb", "message": "ciao da svcb", "tls_peer": "svca.mesh.local"}
  ]
}
```

Il loop `Ping` autonomo svca↔svcb (caso d'uso 5) resta invariato e continua
a girare in parallelo: `Hello`/`Chain` sono RPC aggiuntive dello stesso
servizio `Mesh`, non una sostituzione.

**10. Syslog cifrato (tutti gli host → logserver)**
```bash
kathara connect logserver
tail -f /var/log/remote/appserver/*.log
```

## Stato di validazione

Tutto quanto segue è stato validato staticamente in fase di sviluppo (fuori
da Kathará, che richiede Docker e non è disponibile nell'ambiente in cui
questo laboratorio è stato scritto):

- sintassi di tutti gli script `.startup`/`.sh` (`bash -n`)
- sintassi di tutti gli script Python (`py_compile`)
- generazione PKI end-to-end reale (CA + 7 certificati leaf, verifica catena)
- configurazione `apigw` (nginx -t, con un vhost equivalente)
- configurazione `mailsrv` (postconf)
- configurazione `logserver`/rsyslog client e server (rsyslogd -N1)
- configurazione sshd di `bastion`/`ftpsrv`/`backupsrv` (sshd -t)
- il file `.proto` del service mesh (con le RPC `Hello`/`Chain` aggiunte
  nell'integrazione apigw↔mesh): compilato realmente, stub verificati
- **il servizio mTLS/gRPC (`svca`↔`svcb`): eseguito realmente in locale come
  due processi separati, con scambio di messaggi bidirezionale autenticato
  con i certificati reali generati da `gen_pki.sh`** — in questo processo
  sono stati trovati e corretti due bug reali (terminazione prematura del
  processo quando nessun peer è configurato; verifica hostname del
  certificato che richiede l'IP/hostname reale del peer, non un IP di
  loopback arbitrario)
- **il bridge apigw↔mesh (caso d'uso 9): eseguito realmente in locale**,
  `svca`/`svcb` come sopra più un terzo processo che riusa il vero
  certificato di `apigw` (`pki/apigw.crt`/`.key`, quello già emesso con
  `extendedKeyUsage=serverAuth,clientAuth` da `gen_pki.sh`) come client
  mTLS — `Hello` e `Chain` chiamati realmente via gRPC, `Chain` verificato
  end-to-end incluso l'inoltro reale svca→svcb e il CN del peer mTLS
  estratto correttamente a ogni hop (`apigw.katharalab.local` poi
  `svca.mesh.local`); il bridge HTTP→gRPC di `grpc_proxy.py` è stato
  eseguito realmente come server HTTP e interrogato con richieste reali
  (`/api/mesh/hello`, `/api/mesh/chain`, 404 sulle route inesistenti);
  la nuova `location /api/mesh/` di `apigw.conf` è stata verificata con
  `nginx -t` reale sullo stesso vhost, stesso certificato del lab. Non
  eseguito in questo processo: la connessione via i veri IP di rete del
  mesh (10.4.0.x, che richiedono i container Kathará) — il test locale usa
  loopback con `grpc.ssl_target_name_override`, esattamente il meccanismo
  già previsto da `mesh_node.py` per questo scenario
- **le configurazioni strongSwan (`swanctl.conf`): caricate realmente da
  un demone `charon-systemd` in esecuzione**, sia il profilo PSK
  road-warrior di `mainfw` sia il profilo a certificato ECDSA
  site-to-site di `vpnlocal` — `swanctl --load-all`/`--list-conns` puliti.
  In questo processo è stato scoperto e corretto un conflitto reale tra i
  pacchetti `strongswan` (che dipende da `strongswan-starter`) e
  `strongswan-swanctl` (che lo dichiara `Breaks`/`Replaces`): la prima
  versione del Dockerfile installava entrambi, causando un demone che non
  caricava nessun plugin crittografico e nessun socket VICI — vedi
  Troubleshooting nel `TUTORIAL.md`.

Non validato in questo ambiente (richiede un host con Kathará e Docker):
l'avvio effettivo dei 16 container, l'instaurazione reale dei tunnel IPsec
attraverso l'infrastruttura di rete simulata (il caricamento delle
configurazioni è stato validato con un demone reale, la negoziazione
IKE/ESP end-to-end no, perché richiede due container di rete realmente
isolati e instradati come nel lab), il funzionamento delle ACL iptables in
condizioni di traffico reale, il routing end-to-end tra tutti i segmenti.

## Note

- Le password/PSK nei file di secrets sono in chiaro per finalità di
  laboratorio — mai in produzione (vedi commenti nei file stessi).
- Se l'host di build non ha connettività verso `download.opensuse.org`
  (repository Zeek), commentare il blocco Zeek nei Dockerfile interessati
  (`strongswan`, `router`, `bastion`) e installare Zeek manualmente, oppure
  fornire un mirror interno.
- I sensori scrivono dati grezzi (log Zeek, output di `swanctl --list-sas`)
  sotto `/shared/<hostname>/`, senza alcuna elaborazione o aggregazione
  locale: questa fase è stata deliberatamente rimossa (era basata su
  `pipeline_cbom`, non più in uso in questa versione del laboratorio) per
  concentrarsi sull'infrastruttura di rete e sul paradigma distribuito di
  raccolta. Un'eventuale fase di analisi è un problema separato, da
  affrontare in seguito.