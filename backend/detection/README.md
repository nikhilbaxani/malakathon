# Reglas locales de detección

El motor `RuleBasedDetectionEngine.detect(events, detected_at=...)` acepta eventos
normalizados de **una sola partición** que el servicio ya haya filtrado por intervalo
y por `as_of`. Sus IDs son deterministas para el mismo conjunto de evidencias. No
consulta fuentes externas ni ejecuta acciones de contención.

Estas señales son un vocabulario **local del prototipo**, no un formato oficial. El
adaptador de ingesta debe mapear las columnas recibidas a `Event.event_type` y
`Event.attributes` de forma explícita. Solo se correlacionan eventos con `user` y
`host` no vacíos, ambos cadenas de texto.

| Regla | Señal exacta | Umbral y evidencia |
| --- | --- | --- |
| `privilege_escalation_v1` | `privilege_change`, `outcome=success`, `old_role` distinto de `admin`/`administrator`/`root`, `new_role` igual a uno de ellos | 1 evento. Registra el cambio de rol; su carácter malicioso sigue siendo hipótesis. |
| `possible_exfiltration_v1` | `data_transfer`, `direction=outbound`, `destination_scope=external`, `bytes` entero positivo JSON o cadena de dígitos decimales ASCII positiva (CSV) | Al menos 10 MiB acumulados para el mismo usuario y host en hasta 10 minutos. Cada transferencia contribuye a un lote como máximo. El destino externo y el conteo de bytes se toman del registro; exfiltración sigue siendo hipótesis. |
| `possible_sabotage_v1` | `backup_deleted`, `audit_logging_disabled` o `service_stopped` con `outcome=success` | 1 evento. La operación se observó; su intención de sabotaje sigue siendo hipótesis. |

Las alertas del mismo usuario y host cuya separación consecutiva no supera una
hora forman un incidente abierto. Cada alerta e incidente incluye únicamente los
`event_id` recibidos. Los eventos sin campos requeridos o con señal ambigua no
activan estas reglas. Los textos de alerta distinguen el hecho registrado de la
hipótesis de amenaza. Los umbrales son ajustes iniciales del prototipo, pendientes
de validación con el dataset y la verdad de referencia del evento.

## Grafo forense

`build_attack_graph(incident, alerts, events, *, as_of=None, max_nodes=120)`
devuelve un diccionario JSON con `nodes`, `edges` y `metadata`. Usa un
`networkx.DiGraph`, con IDs de nodo calculados de partición, tipo y valor.
Acepta solamente referencias de alerta y evento que resuelvan dentro de la
partición del incidente. Los registros duplicados idénticos se reúnen; los
conflictivos se rechazan. Un corte `as_of` excluye una alerta completa si
cualquiera de sus evidencias ocurrió después del corte.

| Relación | Requisito del evento | Base |
| --- | --- | --- |
| `HAS_USER`, `HAS_HOST`, `OBSERVED_ON` | `user` y/o `host` explícitos y no vacíos; `OBSERVED_ON` exige ambos en el mismo evento | `observed` |
| `DESTINATION_IP`, `CONNECTED_TO` | `network_connection` o `data_transfer` con `destination_ip` válida; `CONNECTED_TO` exige además `host` y `outcome=success`. El destino se conserva aunque la conexión haya fallado. | `observed` |
| `HAS_PROCESS` | `process_start`, `file_write` o `file_delete` con `process` explícito | `observed` |
| `WROTE_FILE`, `DELETED_FILE` | `file_write` o `file_delete` con `file_path` explícita y `outcome=success` | `observed` |
| `ATTEMPTED_WRITE_FILE`, `ATTEMPTED_DELETE_FILE`, `TARGET_FILE` | Para `file_write`/`file_delete` con `file_path`: `denied`/`failure` expresa intento; resultado ausente o desconocido solo expresa el archivo objetivo | `observed` |
| `EVIDENCE_FOR`, `PART_OF` | Referencias validadas de `Alert.evidence_event_ids` e `Incident.alert_ids` | `derived` |

Cada arista conserva `evidence_event_ids`, intervalo UTC y `provenance` con
`event_id`, `source`, `raw_ref` y `source_timestamp` literal; añade
`source_event_id` y `source_record_number` cuando existen. La coexistencia de usuario y host no demuestra
autenticación. El grafo nunca crea esa relación. `max_nodes` limita la salida:
conserva primero incidente, alertas y eventos, informa de truncamiento y no
devuelve aristas cuyos extremos se hayan omitido. Los datos sin semántica
explícita permanecen fuera del grafo. Este límite se aplica a la salida tras
construir el grafo completo, por lo que no acota el coste de construcción para
incidentes grandes.
