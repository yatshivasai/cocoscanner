#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
sudo apt update
sudo apt install -y python3-tk python3-venv python3-pip nmap libpcap-dev iproute2
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
mkdir -p data
[ -f data/devices.json ] || printf '[]\\n' > data/devices.json
[ -f data/packets.json ] || printf '[]\\n' > data/packets.json
echo "Setup complete. Launch with ./run.sh"

[ -f data/alerts.json ] || printf '[]\\n' > data/alerts.json
[ -f data/rules.json ] || cat > data/rules.json <<'RULES'
[
  {"id":"NET-001","name":"Possible port sweep","enabled":true,"severity":"MEDIUM","threshold":20,"window_seconds":60},
  {"id":"NET-002","name":"DNS query observed","enabled":true,"severity":"INFO","threshold":1,"window_seconds":60}
]
RULES
