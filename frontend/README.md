# Consola Streamlit

Con la API FastAPI activa:

```bash
streamlit run frontend/app.py
```

Por defecto consulta `http://127.0.0.1:8000`. Para otro destino, define
`GSEC_API_BASE_URL`. Selecciona `dataset_kind` e introduce un `dataset_id` real
de la partición ingestada. La consola no incluye datos de ejemplo inventados.

El replay envía `as_of` en **cada** página de eventos y descarta cualquier
evento que una API defectuosa devolviera después del corte. Las alertas e
incidentes del replay provienen de la respuesta transitoria de la detección
con ese corte, sin consultar las colecciones persistidas, y solo aparecen si
toda su evidencia está entre los eventos visibles. No se abre el
detalle de incidente en replay porque ese endpoint no tiene `as_of`.
Triage y contención simulada se ofrecen únicamente en la vista actual.

En la vista actual, la consola muestra alertas e incidentes solo de la última
detección completa ejecutada para esa partición en la sesión del navegador.
El replay histórico no se persiste ni se mezcla con los hallazgos actuales.

La pestaña **Attack Graph** consulta el grafo del incidente seleccionado con
la misma partición y el mismo corte UTC. El dibujo funciona sin CDN y permite
zoom, arrastre, filtros por tipo y dos disposiciones. Se limita a 120 nodos;
los metadatos de la API indican truncamiento y limitaciones. Debajo se pueden
inspeccionar nodos, relaciones y los eventos que fundamentan cada relación.
En replay no se consulta el detalle persistido del incidente.
