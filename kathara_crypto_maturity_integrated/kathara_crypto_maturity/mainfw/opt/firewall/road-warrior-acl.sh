#!/usr/bin/env bash
# road-warrior-acl.sh — ACL IP-based sui pool assegnati dinamicamente dal
# concentratore IKEv2. Eseguito da mainfw.startup dopo l'avvio di strongSwan.
#
# Politica:
#   employee-pool (10.9.1.0/24) -> SOLO verso la DMZ (10.1.0.0/24)
#   admin-pool    (10.9.2.0/24) -> DMZ (10.1.0.0/24) + bastion host
#                                  (10.3.0.2/32, unico host della rete
#                                  netmgmt raggiungibile), MAI direttamente
#                                  verso la LAN interna: quella resta
#                                  raggiungibile solo attraversando il
#                                  bastion via SSH (accesso controllato).
#   tutto il resto in FORWARD dai due pool -> DROP esplicito.
set -euo pipefail

EMPLOYEE_POOL="10.9.1.0/24"
ADMIN_POOL="10.9.2.0/24"
DMZ_NET="10.1.0.0/24"
BASTION_HOST="10.3.0.2/32"

iptables -N RW_ACL 2>/dev/null || iptables -F RW_ACL

# Traffico di ritorno delle sessioni già stabilite: sempre permesso.
iptables -A RW_ACL -m state --state ESTABLISHED,RELATED -j ACCEPT

# employee: solo verso la DMZ
iptables -A RW_ACL -s "$EMPLOYEE_POOL" -d "$DMZ_NET" -j ACCEPT

# admin: DMZ + bastion (unico host raggiungibile in netmgmt)
iptables -A RW_ACL -s "$ADMIN_POOL" -d "$DMZ_NET"      -j ACCEPT
iptables -A RW_ACL -s "$ADMIN_POOL" -d "$BASTION_HOST"  -j ACCEPT

# default: nega esplicitamente qualunque altra destinazione dai due pool
iptables -A RW_ACL -s "$EMPLOYEE_POOL" -j DROP
iptables -A RW_ACL -s "$ADMIN_POOL"    -j DROP

# aggancio della catena alla FORWARD, solo per traffico originato dai pool VPN
iptables -C FORWARD -s "$EMPLOYEE_POOL" -j RW_ACL 2>/dev/null || \
    iptables -I FORWARD -s "$EMPLOYEE_POOL" -j RW_ACL
iptables -C FORWARD -s "$ADMIN_POOL" -j RW_ACL 2>/dev/null || \
    iptables -I FORWARD -s "$ADMIN_POOL" -j RW_ACL

echo "[road-warrior-acl] ACL applicata: employee->DMZ, admin->DMZ+bastion"
