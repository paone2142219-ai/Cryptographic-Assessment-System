#!/usr/bin/env bash
# gen_pki.sh — genera la CA di laboratorio e i certificati leaf per i servizi TLS.
# Eseguire UNA VOLTA sull'host, prima di `kathara lstart`, dalla root del laboratorio.
#
# Convenzione: ogni certificato leaf finisce sotto <machine>/etc/pki/{cert,key,ca}.pem
# nella struttura del lab, cioè nel path che Kathará monta come /etc/pki/... dentro
# quella macchina. La CA privata (ca.key) NON viene copiata in nessuna macchina.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="$ROOT/pki"
mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

echo "[gen_pki] Generazione CA di laboratorio (ECDSA P-384)..."
openssl ecparam -name secp384r1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha384 -days 1825 \
    -subj "/C=IT/O=KatharaLab/CN=KatharaLab Root CA" \
    -out ca.crt

# ── Funzione di utilità: genera cert leaf ECDSA P-256 firmato dalla CA ──
issue_ecdsa () {
    local name="$1" cn="$2" sans="$3"
    openssl ecparam -name prime256v1 -genkey -noout -out "${name}.key"
    openssl req -new -key "${name}.key" -subj "/C=IT/O=KatharaLab/CN=${cn}" -out "${name}.csr"
    openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 825 -sha256 -out "${name}.crt" \
        -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth" "$sans")
    rm -f "${name}.csr"
}

# ── Funzione di utilità: genera cert leaf RSA-2048 (scelta realistica, non best-practice) ──
issue_rsa () {
    local name="$1" cn="$2" sans="$3"
    openssl genrsa -out "${name}.key" 2048 2>/dev/null
    openssl req -new -key "${name}.key" -subj "/C=IT/O=KatharaLab/CN=${cn}" -out "${name}.csr"
    openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 825 -sha256 -out "${name}.crt" \
        -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth" "$sans")
    rm -f "${name}.csr"
}

echo "[gen_pki] apigw — ECDSA P-256 (API gateway, TLS 1.3)"
issue_ecdsa apigw "apigw.katharalab.local" "DNS:apigw.katharalab.local,IP:10.1.0.10"

echo "[gen_pki] mailsrv — RSA-2048 (scelta comune, non ottimale: utile a scopo di assessment)"
issue_rsa mailsrv "mailsrv.katharalab.local" "DNS:mailsrv.katharalab.local,IP:10.1.0.11"

echo "[gen_pki] appserver (client SMTP/STARTTLS, cert opzionale non richiesto lato client)"

echo "[gen_pki] logserver — ECDSA P-256 (syslog TLS)"
issue_ecdsa logserver "logserver.katharalab.local" "DNS:logserver.katharalab.local,IP:10.2.0.12"

echo "[gen_pki] svca / svcb — ECDSA P-256 (mTLS gRPC service mesh)"
issue_ecdsa svca "svca.mesh.local" "DNS:svca.mesh.local,IP:10.4.0.10"
issue_ecdsa svcb "svcb.mesh.local" "DNS:svcb.mesh.local,IP:10.4.0.11"

echo "[gen_pki] vpnlocal / vpnremote — ECDSA P-256 (IPsec site-to-site, autenticazione a certificato)"
issue_ecdsa vpnlocal  "vpnlocal.katharalab.local"  "DNS:vpnlocal.katharalab.local,IP:10.5.0.1,IP:10.8.0.2"
issue_ecdsa vpnremote "vpnremote.katharalab.local" "DNS:vpnremote.katharalab.local,IP:10.5.0.2,IP:192.168.0.1"
echo "[gen_pki] Distribuzione certificati nelle cartelle macchina del lab..."
cd "$ROOT"
for pair in "apigw:apigw" "mailsrv:mailsrv" "logserver:logserver" \
            "svca:svca" "svcb:svcb" "vpnlocal:vpnlocal" "vpnremote:vpnremote"; do
    machine="${pair%%:*}"; certname="${pair##*:}"
    mkdir -p "$machine/etc/pki"
    cp "pki/${certname}.crt" "$machine/etc/pki/cert.pem"
    cp "pki/${certname}.key" "$machine/etc/pki/key.pem"
    cp "pki/ca.crt"          "$machine/etc/pki/ca.pem"
    chmod 600 "$machine/etc/pki/key.pem"
done

# La CA (solo pubblica) va distribuita anche ai client/verificatori che non hanno un
# proprio cert leaf, per validare le controparti.
for machine in clientext appserver bastion mainfw dmzgw internalgw ftpsrv remotehost backupsrv; do
    mkdir -p "$machine/etc/pki"
    cp "pki/ca.crt" "$machine/etc/pki/ca.pem"
done

echo "[gen_pki] Completato. CA privata: $PKI_DIR/ca.key (NON distribuita alle macchine)."
