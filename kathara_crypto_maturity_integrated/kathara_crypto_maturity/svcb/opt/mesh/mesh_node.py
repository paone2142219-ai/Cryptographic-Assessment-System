#!/usr/bin/env python3
"""
mesh_node.py — nodo del service mesh (usato sia da svca sia da svcb).

Ogni nodo espone il servizio Mesh su gRPC richiedendo l'autenticazione
mutua del client (mTLS: il server verifica il certificato del client
contro la CA di laboratorio, non solo viceversa), ed è al tempo stesso:

  - client verso il peer (svca<->svcb), in un loop Ping che genera
    traffico osservabile con cadenza regolare — invariato rispetto alla
    versione originale del laboratorio;
  - server per chiamate Hello/Chain in ingresso da un chiamante esterno
    al mesh, autenticato mTLS. Nel laboratorio integrato questo
    chiamante è l'apigw (bridge HTTP -> gRPC/mTLS), ma il servicer non fa
    assunzioni su chi sia: verifica solo che il certificato client sia
    valido contro la CA, come per il traffico Ping.

Variabili d'ambiente:
  MESH_SERVICE_NAME   nome di questo servizio (es. "svca")
  MESH_PEER_HOST      host del peer da chiamare (es. "10.4.0.11")
  MESH_PEER_PORT      porta gRPC del peer (default 50051)
  MESH_LISTEN_PORT    porta di ascolto locale (default 50051)
  MESH_CERT_DIR       cartella con cert.pem/key.pem/ca.pem (default /etc/pki)
"""

import logging
import os
import sys
import time
from concurrent import futures

import grpc

sys.path.insert(0, os.path.dirname(__file__))
import mesh_pb2
import mesh_pb2_grpc

logging.basicConfig(level=logging.INFO, format="[%(name)s] %(message)s")
log = logging.getLogger(os.environ.get("MESH_SERVICE_NAME", "mesh"))

CERT_DIR = os.environ.get("MESH_CERT_DIR", "/etc/pki")
SERVICE_NAME = os.environ.get("MESH_SERVICE_NAME", "unknown")
PEER_HOST = os.environ.get("MESH_PEER_HOST")
PEER_PORT = os.environ.get("MESH_PEER_PORT", "50051")
LISTEN_PORT = os.environ.get("MESH_LISTEN_PORT", "50051")


def _read(name: str) -> bytes:
    with open(os.path.join(CERT_DIR, name), "rb") as fh:
        return fh.read()


def _peer_cn(context) -> str:
    """Estrae il CN dal certificato X.509 del peer mTLS del chiamante
    corrente (funziona per qualunque client autenticato: apigw, l'altro
    nodo del mesh, ecc.)."""
    auth_ctx = context.auth_context()
    pem_list = auth_ctx.get("x509_pem_cert", [])
    if not pem_list:
        return "unknown"
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_pem_x509_certificate(pem_list[0], default_backend())
    return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value


def _peer_channel_creds():
    cert = _read("cert.pem")
    key = _read("key.pem")
    ca = _read("ca.pem")
    return grpc.ssl_channel_credentials(
        root_certificates=ca,
        private_key=key,
        certificate_chain=cert,
    )


def _peer_channel_options():
    # Il nome verificato contro il SAN del certificato del peer coincide
    # con PEER_HOST (il suo IP è nel SAN — vedi gen_pki.sh), quindi non
    # serve override salvo test in loopback (MESH_PEER_TLS_NAME).
    peer_tls_name = os.environ.get("MESH_PEER_TLS_NAME", PEER_HOST)
    if peer_tls_name != PEER_HOST:
        return (("grpc.ssl_target_name_override", peer_tls_name),)
    return ()


class MeshServicer(mesh_pb2_grpc.MeshServicer):

    def Ping(self, request, context):
        log.info(f"Ping ricevuto da {request.from_service} (seq={request.sequence})")
        return mesh_pb2.PingReply(
            from_service=SERVICE_NAME,
            sequence=request.sequence,
            message=f"pong da {SERVICE_NAME}",
        )

    def Hello(self, request, context):
        peer_cn = _peer_cn(context)
        log.info(f"Hello() <- caller={request.caller} peer_cn={peer_cn}")
        return mesh_pb2.HelloReply(
            node=SERVICE_NAME,
            message=f"ciao da {SERVICE_NAME}",
            tls_peer=peer_cn,
        )

    def Chain(self, request, context):
        peer_cn = _peer_cn(context)
        log.info(f"Chain() <- origin={request.origin} peer_cn={peer_cn}")

        # Hop locale: risposta di questo nodo.
        hop_local = mesh_pb2.HelloReply(
            node=SERVICE_NAME,
            message=f"{SERVICE_NAME} ha ricevuto la chain",
            tls_peer=peer_cn,
        )
        hops = [hop_local]
        path = f"{request.origin} -> {SERVICE_NAME}"

        # Se questo nodo ha un peer nel mesh, inoltra una Hello mTLS e
        # aggrega la risposta (dimostra l'hop successivo apigw->svca->svcb).
        if PEER_HOST:
            try:
                with grpc.secure_channel(
                    f"{PEER_HOST}:{PEER_PORT}",
                    _peer_channel_creds(),
                    options=_peer_channel_options(),
                ) as channel:
                    stub = mesh_pb2_grpc.MeshStub(channel)
                    hop_peer = stub.Hello(
                        mesh_pb2.HelloRequest(caller=SERVICE_NAME), timeout=5
                    )
                    hops.append(hop_peer)
                    path += f" -> {hop_peer.node}"
            except grpc.RpcError as exc:
                log.warning(f"Chain: peer {PEER_HOST}:{PEER_PORT} fallito: {exc.code()}")
                hops.append(mesh_pb2.HelloReply(
                    node="?", message=f"ERROR: {exc.code()}", tls_peer=""
                ))

        return mesh_pb2.ChainReply(path=path, hops=hops)


def serve():
    cert = _read("cert.pem")
    key = _read("key.pem")
    ca = _read("ca.pem")

    # require_client_auth=True è il punto qualificante: senza, sarebbe TLS
    # server-only (autenticazione di una sola direzione), non mutual TLS.
    server_creds = grpc.ssl_server_credentials(
        [(key, cert)],
        root_certificates=ca,
        require_client_auth=True,
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    mesh_pb2_grpc.add_MeshServicer_to_server(MeshServicer(), server)
    server.add_secure_port(f"0.0.0.0:{LISTEN_PORT}", server_creds)
    server.start()
    log.info(f"in ascolto su :{LISTEN_PORT} (mTLS, client auth richiesta)")
    return server


def client_loop():
    if not PEER_HOST:
        log.info("MESH_PEER_HOST non impostato, nessun client loop avviato")
        return

    channel_creds = _peer_channel_creds()
    channel_options = _peer_channel_options()

    seq = 0
    while True:
        try:
            with grpc.secure_channel(f"{PEER_HOST}:{PEER_PORT}", channel_creds,
                                      options=channel_options) as channel:
                stub = mesh_pb2_grpc.MeshStub(channel)
                seq += 1
                reply = stub.Ping(
                    mesh_pb2.PingRequest(from_service=SERVICE_NAME, sequence=seq),
                    timeout=5,
                )
                log.info(f"risposta da {reply.from_service}: {reply.message} (seq={reply.sequence})")
        except grpc.RpcError as exc:
            log.warning(f"chiamata verso {PEER_HOST}:{PEER_PORT} fallita: {exc.code()}")
        time.sleep(15)


if __name__ == "__main__":
    srv = serve()
    try:
        if PEER_HOST:
            client_loop()
        else:
            # Nessun peer configurato: il nodo resta comunque attivo come
            # server. Senza questa attesa esplicita il processo terminava
            # subito dopo serve(), chiudendo il server proprio mentre un
            # client stava tentando la connessione (causa reale del
            # fallimento "Stream removed (Socket closed)" osservato in test).
            srv.wait_for_termination()
    except KeyboardInterrupt:
        srv.stop(0)
