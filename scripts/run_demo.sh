#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

demo_python="$root_dir/.venv/bin/python"
api_port="${GSEC_DEMO_API_PORT:-8000}"
ui_port="${GSEC_DEMO_UI_PORT:-8501}"
for port in "$api_port" "$ui_port"; do
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        echo "Puerto inválido: $port" >&2
        exit 2
    fi
done
if [[ "$api_port" == "$ui_port" ]]; then
    echo "API y consola necesitan puertos distintos." >&2
    exit 2
fi
if [[ ! -x "$demo_python" ]]; then
    echo "Falta .venv. Instala el proyecto: python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'" >&2
    exit 2
fi
if ! "$demo_python" -c 'import uvicorn, streamlit, fastapi, duckdb, networkx' >/dev/null 2>&1; then
    echo "Faltan dependencias. Ejecuta: .venv/bin/python -m pip install -e '.[dev]'" >&2
    exit 2
fi

port_is_busy() {
    "$demo_python" -c 'import socket,sys
try:
    connection = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.25)
except OSError:
    raise SystemExit(1)
else:
    connection.close()
    raise SystemExit(0)' "$1"
}
for port in "$api_port" "$ui_port"; do
    if port_is_busy "$port"; then
        echo "El puerto 127.0.0.1:$port ya está ocupado. No se detendrá ningún proceso ajeno." >&2
        exit 2
    fi
done

mkdir -p "$root_dir/data/demo_runs"
runtime_dir="$(mktemp -d "$root_dir/data/demo_runs/run-XXXXXXXX")"
export GSEC_DATA_DIR="$runtime_dir"
export GSEC_DUCKDB_PATH="$runtime_dir/sentinel.duckdb"
export GSEC_API_BASE_URL="http://127.0.0.1:$api_port"
# The reproducible demo always uses local deterministic triage.
export GSEC_ENABLE_JEV=0

api_pid=""
ui_pid=""
cleanup() {
    trap - EXIT INT TERM
    for pid in "$ui_pid" "$api_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$ui_pid" "$api_pid"; do
        if [[ -n "$pid" ]]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT INT TERM

wait_for_url() {
    local url="$1"
    local pid="$2"
    for _ in {1..50}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        if "$demo_python" -c 'import sys,urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=1) as response:
    raise SystemExit(0 if response.status == 200 else 1)' "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

"$demo_python" -m uvicorn backend.api.app:app --host 127.0.0.1 --port "$api_port" >"$runtime_dir/api.log" 2>&1 &
api_pid=$!
if ! wait_for_url "$GSEC_API_BASE_URL/health" "$api_pid"; then
    echo "La API no arrancó. Revisa $runtime_dir/api.log" >&2
    exit 1
fi

"$demo_python" -m streamlit run frontend/app.py \
    --server.address 127.0.0.1 --server.port "$ui_port" \
    --server.headless true --browser.gatherUsageStats false >"$runtime_dir/ui.log" 2>&1 &
ui_pid=$!
if ! wait_for_url "http://127.0.0.1:$ui_port" "$ui_pid"; then
    echo "La consola no arrancó. Revisa $runtime_dir/ui.log" >&2
    exit 1
fi

echo "API:      $GSEC_API_BASE_URL/docs"
echo "Consola:  http://127.0.0.1:$ui_port"
echo "Datos:    $runtime_dir"
echo "Carga:    .venv/bin/python -m scripts.load_demo --api-url $GSEC_API_BASE_URL"
echo "Pulsa Ctrl+C para detener los dos procesos iniciados por este script."
wait -n "$api_pid" "$ui_pid"
