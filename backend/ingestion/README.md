# Adaptador local CSV/JSONL

`CsvJsonlIngestor.ingest` recibe bytes UTF-8, la partición (`dataset_kind`,
`dataset_id`), `source` y un `field_mapping` explícito. Las claves canónicas del
mapeo son `source_timestamp`, `event_type` y, opcionalmente,
`source_event_id`. Las columnas no consumidas se copian a `Event.attributes`
con sus nombres originales; JSONL conserva los tipos JSON y CSV aporta texto.
No hay un mapeo implícito para datos oficiales.

Se guarda el archivo exacto antes de analizarlo. `raw_ref` apunta a ese archivo,
y `source_record_number` empieza en 1 para los registros de datos, sin contar
la cabecera CSV. Cada error de registro conserva ambos datos. El almacén bruto
guarda los metadatos del archivo en un sidecar JSON inmutable.

Se aceptan fechas ISO 8601 con zona horaria y se convierten a UTC. Una fecha
sin zona o ilegible queda en cuarentena; no se supone una zona. Una entrada que
no sea UTF-8 produce un error de lote con número de registro 1. Un error de
estructura CSV que impida reanudar la lectura detiene el resto del archivo.

El ID interno se deriva de partición, `source` e ID de origen cuando existe.
Sin ID de origen, se deriva de la referencia del archivo y del número de
registro. Reingestas equivalentes no duplican eventos. Si se repite un ID de
origen con otros datos, el registro nuevo queda en cuarentena; se conserva el
primero. El primer `raw_ref` es el que se devuelve al consultar el evento.

Las consultas DuckDB tienen índice de partición y tiempo. El adaptador procesa
los registros de manera individual para aislar errores; cargas muy grandes
podrían requerir una ruta de inserción por lotes. No existe todavía una política
confirmada para codificaciones, identificadores o zonas horarias del dataset
oficial.
