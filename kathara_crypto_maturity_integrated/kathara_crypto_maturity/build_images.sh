#!/usr/bin/env bash
# build_images.sh — costruisce tutte le immagini Docker custom usate da
# lab.conf. Da eseguire UNA VOLTA prima di `kathara lstart` (e di nuovo
# solo se si modificano i Dockerfile).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT/images"

declare -A IMAGES=(
    [strongswan]=Dockerfile.strongswan
    [router]=Dockerfile.router
    [bastion]=Dockerfile.bastion
    [nginx-tls]=Dockerfile.nginx-tls
    [postfix]=Dockerfile.postfix
    [sftp]=Dockerfile.sftp
    [rsyslog-tls]=Dockerfile.rsyslog-tls
    [appserver]=Dockerfile.appserver
    [grpc-mesh]=Dockerfile.grpc-mesh
    [plain]=Dockerfile.plain
)

for name in "${!IMAGES[@]}"; do
    dockerfile="${IMAGES[$name]}"
    tag="kathara-crypto-maturity/${name}:latest"
    echo "── build ${tag} (${dockerfile}) ──────────────────────────"
    docker build -f "$dockerfile" -t "$tag" .
done

echo "Tutte le immagini sono state costruite."
docker images | grep kathara-crypto-maturity
