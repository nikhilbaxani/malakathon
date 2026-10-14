# GSEC Sentinel: contratos de integración (fase 1)

Estado: propuesta local para el prototipo, 14 de octubre de 2026. Los formatos del
dataset, el mecanismo oficial de contención, la API de TypeSafe Jev y la posible
obligación de OCI siguen sin confirmar. Ningún campo de este documento pretende
describir telemetría oficial.

## Flujo y límites

```text
archivo local -> adaptador de formato -> registro bruto inmutable -> Event -> DuckDB
                                                                |          |
                                                         detector -> Alert -> Incident
                                                                               |
                                               triage determinista/Jev opcional -> TriageResult
                                                                               |
                                                consola -> ContainmentAction (simulación)
```

FastAPI coordina los casos de uso y sirve JSON. Streamlit consume su API HTTP; no
abre DuckDB ni llama a Jev directamente. El almacén local usa DuckDB para índices
y consultas, y archivos locales para el contenido original. OCI, si resulta
necesario, sustituye únicamente el adaptador de almacenamiento pertinente.
El primer corte vertical es ingesta local -> detección determinista -> incidente
-> triage determinista -> consola -> acción simulada. Jev y OCI son adaptadores
opcionales sujetos a los requisitos que se confirmen durante el evento.

## Modelos compartidos

Los esquemas ejecutables están en `backend/models.py`. Todos rechazan campos
desconocidos y fechas sin zona horaria. Las fechas derivadas se convierten a UTC.

| Modelo | Campos y reglas esenciales |
| --- | --- |
| `Event` | `event_id` interno estable, `dataset_id`, `dataset_kind`, `source`, `source_event_id` opcional sin modificar, `source_timestamp` literal sin modificar, `source_record_number` opcional, `timestamp_utc`, `event_type`, `raw_ref`, `attributes` JSON. |
| `IngestionResult` / `IngestionIssue` | Lote y partición, IDs aceptados, errores con número de registro lógico, referencia al original y motivo. |
| `Alert` | `alert_id`, partición de dataset, `rule_id`, título, descripción, severidad, `detected_at`, `evidence_event_ids` no vacía. Cada ID debe resolver a un `Event` de la misma partición. |
| `Incident` | `incident_id`, partición, título, estado, `created_at`, `alert_ids` y `evidence_event_ids` no vacías. Las referencias deben resolver dentro de la misma partición. |
| `DetectionResult` | Alertas e incidentes producidos por una ejecución; la API persiste y devuelve sus IDs. |
| `TriageResult` | `triage_id`, `incident_id`, `engine` (`deterministic` o `jev`), `assessment`, resumen, razonamiento, `generated_at`, `evidence_event_ids` no vacía. Sus conclusiones son evaluación, no hechos de telemetría. |
| `ContainmentAction` | `action_id`, `incident_id`, tipo, objetivo, `mode`, estado, fecha, `evidence_event_ids`. En modo `live` se exigen identificador de aprobación, autorizador y fecha; una verificación de permisos en el servicio sigue siendo obligatoria antes de ejecutar. Fase 1 solo registra simulaciones. |

`dataset_kind` es `synthetic` u `official` y nunca se mezcla en correlaciones.
`dataset_id` distingue lotes dentro de cada origen. `event_id` es la clave interna;
si el registro aporta un identificador, se guarda idéntico en `source_event_id`.
El contenido original se almacena aparte sin transformaciones y `raw_ref` apunta
a él. Para archivos con varios registros, `source_record_number` localiza el
registro lógico dentro de los bytes originales, empezando en 1; la ingesta lo
rellena aunque el campo sea opcional para eventos creados por otros adaptadores.
Un registro en cuarentena conserva `raw_ref` y su número de registro. Si falta
una fecha interpretable, se pone en cuarentena con un error; no se inventa un
tiempo del evento. La zona
horaria ausente requiere una regla explícita del adaptador de formato.

El esquema no puede comprobar por sí solo claves foráneas ni la identidad de
quien autoriza. El servicio y la persistencia deben comprobar ambas al escribir.
Una alerta nunca se crea con evidencia ausente. La reproducción hasta un instante
`T` debe calcular resultados solo con `Event.timestamp_utc <= T`. En el primer
corte, `as_of` limita la consulta de eventos y la ejecución de detección. Un
historial persistente de ejecuciones de replay se deja para P2.

## API HTTP mínima propuesta (`/v1`)

| Método y ruta | Propósito |
| --- | --- |
| `GET /health` | Salud del proceso y acceso al almacén. |
| `POST /v1/ingestions` | Recibir archivo CSV/JSONL y mapeo explícito de columnas junto con `dataset_kind` y `dataset_id`; responde con `IngestionResult`. El mapeo oficial se definirá al recibir muestras. |
| `GET /v1/events` | Buscar por partición, intervalo UTC y paginación; `as_of` limita la reproducción. |
| `GET /v1/events/{event_id}` | Evento normalizado y referencia al original, dentro de una partición indicada. |
| `GET /v1/events/{event_id}/raw` | Bytes originales (`application/octet-stream`) del archivo que contiene el evento, dentro de una partición indicada. |
| `POST /v1/detections/run` | Ejecutar reglas deterministas sobre una partición y un intervalo UTC, opcionalmente con corte `as_of`; respuesta con IDs de alertas e incidentes. |
| `GET /v1/alerts` | Consultar alertas con IDs de evidencia. |
| `GET /v1/incidents` | Consultar incidentes y sus estados. |
| `GET /v1/incidents/{incident_id}` | Detalle, evidencias, línea temporal, triage y acciones simuladas. |
| `POST /v1/incidents/{incident_id}/triage` | Evaluación estructurada; usa fallback determinista si Jev no está configurado o falla. |
| `POST /v1/incidents/{incident_id}/containment/simulate` | Registrar una acción simulada, etiquetada como tal. No llama a sistemas externos. |

`POST /v1/ingestions` recibe JSON con `content_base64` (bytes exactos del archivo),
`format` (`csv` o `jsonl`), `dataset_kind`, `dataset_id`, `source` y
`field_mapping` (objeto de nombres canónicos a columnas de entrada). Las claves
canónicas mínimas son `source_timestamp` y `event_type`; `source_event_id` es
opcional. El adaptador valida el mapeo para el archivo recibido, sin asumir un
formato oficial. La respuesta usa `IngestionResult`; los conteos son las longitudes
de `accepted_event_ids` y `errors`. Para un error, `record_number` cuenta
registros lógicos desde 1 y `raw_ref` apunta al archivo original.

`POST /v1/detections/run` recibe JSON con `dataset_kind`, `dataset_id`,
`from_utc`, `to_utc` y `as_of` opcionales; devuelve `alert_ids` e `incident_ids`.
`POST /v1/incidents/{incident_id}/triage` devuelve `TriageResult`.
`POST /v1/incidents/{incident_id}/containment/simulate` recibe `action_type`,
`target` y `evidence_event_ids` y devuelve `ContainmentAction` con
`mode=simulation`. Todas las fechas de entrada son ISO 8601 con zona horaria.

`GET /v1/events`, `/v1/alerts` y `/v1/incidents` devuelven listas JSON de sus
modelos compartidos. El detalle de incidente devuelve un objeto con claves
`incident`, `alerts`, `events`, `triage_results` y `containment_actions`, cada
valor serializado con su modelo compartido; las listas pueden estar vacías.
Así el frontend puede trabajar con JSON de ejemplo de esa misma forma.
Las colecciones y el detalle de incidente exigen `dataset_kind` y `dataset_id`.
La validación de entrada devuelve 422 y una referencia inexistente devuelve 404.
Se evita una ruta de
contención real hasta conocer mecanismo, autorización y requisitos del evento.
La forma exacta del cuerpo de subida se fija al implementar el adaptador y se
documenta en OpenAPI; estos endpoints son el contrato de capacidad de fase 1.

## Puertos de almacenamiento

Las interfaces Python están en `backend/ports.py`:

- `TelemetryIngestor.ingest`: recibe bytes, formato, partición, origen y mapeo;
  guarda el original antes de analizar y devuelve `IngestionResult`.
- `DetectionEngine.detect`: recibe solo eventos de una partición ya filtrados
  por intervalo y `as_of`, más `detected_at` consciente de zona; devuelve
  `DetectionResult`. El coordinador persiste sus alertas e incidentes.
- `TriageEngine.triage`: recibe incidente, alertas y eventos de evidencia
  resueltos en la misma partición, más `generated_at` consciente de zona;
  devuelve `TriageResult`. El coordinador usa Jev solo si su adaptador está
  configurado; si no lo está o falla, usa el motor determinista y registra
  el motor realmente usado.
- `RawTelemetryStore`: `put` conserva bytes originales y metadatos de origen;
  devuelve una referencia durable. `get` recupera exactamente los mismos bytes.
- `SocRepository`: persiste y consulta `Event`, `Alert`, `Incident`,
  `TriageResult` y `ContainmentAction` por partición. El triage y las acciones
  se recuperan por incidente y partición. Rechaza referencias cruzadas y
  evidencia inexistente. La implementación inicial usa DuckDB.

Implementaciones previstas: `LocalRawTelemetryStore` con archivos locales,
`DuckDBSocRepository`; adaptadores OCI futuros implementarán el mismo puerto,
sin introducir dependencia OCI en la lógica de detección o la UI. El almacén
local separa físicamente contenido bruto y tablas normalizadas; las tablas
incluyen `dataset_kind` y `dataset_id` en índices y claves de consulta.

## Reparto y orden de integración

1. **Coordinador** mantiene este contrato, `backend/models.py`, `backend/ports.py`
   y `backend/api/`. Congela los modelos antes de integrar ramas y conecta las
   rutas HTTP con los puertos.
2. **soc_data** posee `backend/ingestion/` y `backend/storage/`: formato local
   CSV/JSONL, cuarentena, UTC, deduplicación, DuckDB y originales. Espera una
   muestra oficial antes de mapear campos oficiales.
3. **soc_hunter** posee `backend/detection/`: reglas sobre `Event`, correlación,
   alertas con IDs verificables e incidentes. Entrega una función determinista
   que acepta partición e intervalo/corte, con pruebas positivas y negativas.
4. **soc_ai** posee `backend/ai/`: triage determinista primero y adaptador Jev
   solo tras verificar documentación/API; timeout, errores y pruebas sin red.
   Devuelve `TriageResult` con evidencia existente y el motor realmente usado.
5. **soc_ui** posee `frontend/`: dashboard, eventos, alertas, incidentes y
   cronología por `as_of` mediante HTTP; muestra evidencia y simulaciones con
   etiquetas explícitas. Usa JSON de ejemplo hasta disponer de las rutas.
6. **soc_reviewer** revisa contratos, integridad, permisos y reproducibilidad
   sin editar. Nadie edita archivos de otro dueño; el coordinador integra y
   ejecuta Git de forma secuencial.

### Primera prueba end-to-end que debe implementar la fase 2

Con un archivo **sintético local inventado y etiquetado para pruebas** de tres
eventos, importarlo por HTTP; verificar que el almacén devuelve los bytes
originales, IDs de origen y fechas UTC; ejecutar una regla de prueba que produzca
una alerta con IDs existentes; abrir un incidente; solicitar triage determinista;
comprobar en la API y la consola el incidente y su evidencia; registrar una
simulación y verificar que no se invocó ningún ejecutor externo. En un almacén
aislado, repetir la consulta y la detección con `as_of` anterior al tercer
evento y asegurar que éste no aparece ni influye en esa ejecución. Esta prueba
aún no existe en fase 1.

## Decisiones pendientes del evento

- Forma, volumen, codificación, huso horario e identificadores del dataset.
- Señales observables para las reglas, umbrales y verdad de referencia.
- API y condiciones de uso de TypeSafe Jev; de no confirmarse, solo fallback.
- Proveedor y alcance de OCI, si se exige.
- Mecanismo, autoridad y auditoría de contención real; requiere aprobación
  expresa antes de cualquier ejecución.
