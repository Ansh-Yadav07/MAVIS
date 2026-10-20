#!/usr/bin/env bash
# Start MAVIS with live monitoring of this Mac in one command:
#   ./scripts/start.sh            # server + sensor on the default network interface
#   ./scripts/start.sh lo0        # sensor on another interface
#
# The server runs as you; only the sensor needs admin rights to read packets, so you are asked
# for your password once. Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
PORT=8000
IFACE="${1:-$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')}"
IFACE="${IFACE:-en0}"

server_pid=""
if curl -s -m 2 "http://127.0.0.1:${PORT}/api/health" >/dev/null; then
  echo "MAVIS server already running on port ${PORT}"
else
  echo "starting MAVIS server on http://localhost:${PORT}"
  "$PY" scripts/serve.py --port "$PORT" --no-browser &
  server_pid=$!
  for _ in $(seq 1 30); do
    curl -s -m 1 "http://127.0.0.1:${PORT}/api/health" >/dev/null && break
    sleep 1
  done
fi

cleanup() { [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

open "http://localhost:${PORT}" 2>/dev/null || true
echo "starting sensor on ${IFACE} (asks for your password)"
sudo "$PY" scripts/sensor.py --iface "$IFACE" --api "http://127.0.0.1:${PORT}"
