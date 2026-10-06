#!/usr/bin/env python3
"""
grpc_proxy.py — ponte HTTP (nginx, locale) -> gRPC/mTLS verso il service
mesh (svca, svcb).

Ascolta in chiaro su 127.0.0.1:8080: nginx termina il TLS 1.3 lato client
(vedi apigw.conf, location /api/mesh/) e inoltra qui in HTTP semplice sulla
loopback. Verso il mesh, questo processo apre un canale gRPC autenticato
mTLS usando lo stesso certificato che apigw già possiede per il proprio
TLS server (/etc/pki/cert.pem, key.pem — emesso con extendedKeyUsage
serverAuth+clientAuth, vedi gen_pki.sh): nessun certificato aggiuntivo da
generare, apigw diventa semplicemente anche client mTLS del mesh.
"""
import json
import logging
import os
import sys

from http.server import HTTPServer, BaseHTTPRequestHandler

import grpc

sys.path.insert(0, os.path.dirname(__file__))
import mesh_pb2
import mesh_pb2_grpc

logging.basicConfig(level=logging.INFO, format="[apigw-grpc-proxy] %(message)s")
log = logging.getLogger("grpc_proxy")

CERT_DIR = os.environ.get("MESH_CERT_DIR", "/etc/pki")

SVCA_ADDR = os.environ.get("SVCA_ADDR", "10.4.0.10:50051")
SVCB_ADDR = os.environ.get("SVCB_ADDR", "10.4.0.11:50051")


def _read(name: str) -> bytes:
    with open(os.path.join(CERT_DIR, name), "rb") as fh:
        return fh.read()


def _channel_creds():
    return grpc.ssl_channel_credentials(
        root_certificates=_read("ca.pem"),
        private_key=_read("key.pem"),
        certificate_chain=_read("cert.pem"),
    )


CREDS = _channel_creds()


def _stub(addr: str):
    # Gli IP dei nodi mesh sono nel SAN del loro certificato (gen_pki.sh),
    # quindi la verifica hostname passa senza override.
    channel = grpc.secure_channel(addr, CREDS)
    return mesh_pb2_grpc.MeshStub(channel), channel


class ProxyHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log.info(fmt % args)

    def _json(self, data: dict, code: int = 200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.rstrip("/")

        # GET /api/mesh/hello -> Hello su svca (mTLS)
        if path == "/api/mesh/hello":
            stub, channel = _stub(SVCA_ADDR)
            try:
                reply = stub.Hello(mesh_pb2.HelloRequest(caller="apigw"), timeout=5)
                self._json({
                    "node": reply.node,
                    "message": reply.message,
                    "tls_peer": reply.tls_peer,
                })
            except grpc.RpcError as exc:
                log.error("gRPC error verso svca: %s", exc)
                self._json({"error": str(exc.code())}, 502)
            finally:
                channel.close()

        # GET /api/mesh/chain -> Chain su svca (svca inoltra a svcb, mTLS a ogni hop)
        elif path == "/api/mesh/chain":
            stub, channel = _stub(SVCA_ADDR)
            try:
                reply = stub.Chain(mesh_pb2.ChainRequest(origin="apigw"), timeout=5)
                self._json({
                    "path": reply.path,
                    "hops": [
                        {"node": h.node, "message": h.message, "tls_peer": h.tls_peer}
                        for h in reply.hops
                    ],
                })
            except grpc.RpcError as exc:
                log.error("gRPC error verso svca: %s", exc)
                self._json({"error": str(exc.code())}, 502)
            finally:
                channel.close()

        else:
            self._json({"error": "route non trovata"}, 404)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8080), ProxyHandler)
    log.info("in ascolto su 127.0.0.1:8080 (bridge verso il mesh gRPC/mTLS)")
    server.serve_forever()
