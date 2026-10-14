# API local

Desde la raíz del repositorio, instala las dependencias y usa el arranque local
reproducible:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
bash scripts/run_demo.sh
```

El script comprueba ambos puertos, crea un almacén aislado por arranque bajo
`data/demo_runs/`, mantiene API y consola en `127.0.0.1`, desactiva Jev para
la demo y detiene solo los procesos que inició al pulsar Ctrl+C. Para arrancar
únicamente la API:

```bash
.venv/bin/python -m uvicorn backend.api.app:app --host 127.0.0.1 --port 8000
```

En otra terminal:

```bash
.venv/bin/python -m streamlit run frontend/app.py --server.address 127.0.0.1 --server.port 8501
```

`GSEC_DUCKDB_PATH` elige la base DuckDB (por defecto `./data/sentinel.duckdb`)
y `GSEC_DATA_DIR` la carpeta de originales (`./data/raw`). El frontend usa
`GSEC_API_BASE_URL`, por defecto `http://127.0.0.1:8000`. `GET /docs` muestra
el esquema HTTP, incluidos el cuerpo de ingesta base64 y el mapeo obligatorio.

El triaje es local por defecto. Para habilitar Jev de forma opcional, instalar
`typesafe-sdk` en el entorno y arrancar la API con `GSEC_ENABLE_JEV=1` y
`GSEC_JEV_API_KEY` en variables de entorno. El adaptador solo envía conteos
agregados de alertas de particiones sintéticas. Sin SDK, clave o respuesta
válida, vuelve al motor determinista. No hay ruta de contención real; la API
únicamente registra simulaciones.

El fixture inventado y marcado como sintético de `tests/test_api_flow.py`
recorre por HTTP ingesta, detección, incidente, triaje, simulación y replay:

```bash
.venv/bin/python -m pytest -q tests/test_api_flow.py
```

Las ejecuciones completas persisten alertas e incidentes. Los cortes con
`as_of`, `from_utc` o `to_utc` devuelven resultados transitorios en la respuesta
HTTP y no alteran las investigaciones actuales. Las versiones de replay que
quedaran en una base creada con código anterior no pueden distinguirse de
incidentes actuales sin procedencia adicional; usa el almacén aislado del
script para la demo. Un historial persistente de replay queda pendiente.

`GET /v1/incidents/{incident_id}/graph` acepta la misma partición y,
opcionalmente, `as_of` y `max_nodes` (1–250, por defecto 120). Devuelve
`nodes`, `edges` y `metadata`: cada arista contiene IDs de eventos,
intervalo temporal, procedencia de los originales y marca `observed` o
`derived`. En replay, la ruta vuelve a calcular la detección con eventos
hasta `as_of` sin persistir resultados. Puede recibir el ID de un incidente
transitorio de ese corte o el ID actual cuando se identifica un único
antecedente histórico. Si ese antecedente aún no existe, devuelve un grafo
vacío con la limitación indicada; un ID ajeno a la partición devuelve 404.
La API no implementa autenticación: mantenla vinculada a loopback con los
comandos anteriores.
