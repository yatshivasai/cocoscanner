#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  echo "NETSENTINEL is not installed. Run ./setup.sh first."
  exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
  echo "The ip command is missing. Install iproute2 with: sudo apt install iproute2"
  exit 1
fi
exec sudo .venv/bin/python netsentinel.py
