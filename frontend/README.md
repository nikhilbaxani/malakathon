# GSEC Sentinel · consola SOC

Con la API FastAPI activa, desde la raíz del repositorio:

```bash
.venv/bin/python -m streamlit run frontend/app.py
```

La consola consulta `http://127.0.0.1:8000` o `GSEC_API_BASE_URL`. Selecciona
el tipo de dataset e introduce el identificador de una partición ya ingestada.
Todos los eventos, hallazgos, grafos, evaluaciones y acciones proceden de HTTP;
el frontend no abre DuckDB, genera telemetría ni llama directamente a Jev.
Los datasets sintéticos están identificados como datos de prueba en todas las vistas.

## Sistema visual

El tema nativo de `.streamlit/config.toml` define charcoal `#0B0F15`, navy
`#141B25`, texto `#E4EAF2` y teal `#46C8BA`. El texto secundario del grafo usa
`#A9B7C9`. Los colores rojo y ámbar quedan reservados para estados de riesgo;
los tipos de entidad se distinguen mediante etiquetas además del color.
La tipografía usa fuentes de sistema sin descargas: sans para lectura y mono
para tiempos, identificadores y evidencia técnica. Las tablas tienen filas de
36 px. Los botones, formularios, pestañas, contenedores y estados son nativos.
`frontend/visual.py` presenta topbar, tarjetas, badges, distribución y feed
como HTML/SVG inerte, escapando todos los valores recibidos. `styles.css`
organiza tokens primitivos, semánticos y de componente. Los estilos de widgets
se limitan a las clases documentadas de `st.container(key=...)` y selectores
semánticos; no se modifican clases internas ni selectores `data-testid`.
Los tres ejemplos de `template_example/` guían la composición: rail compacto,
topbar baja, paneles con borde, KPIs y cola densa. Se aplican UI/UX Pro Max,
Design System y UI Styling a Streamlit, conservando controles accesibles.
No hay animaciones decorativas ni dependencias nuevas.

## Navegación y flujo de trabajo

1. **SOC Overview**: conteos reales de eventos consultados y de la última
   detección completa de la sesión; distribución real de severidad, volumen
   de eventos por día UTC, entidades observadas y cola de alertas con acceso
   **Investigar →**. El feed muestra los últimos seis eventos del snapshot,
   con fecha y hora UTC, sin afirmar que sea un flujo en tiempo real.
2. **Threat Hunting**: filtros por tipo, origen y texto; tabla compacta y
   selección de eventos para consultar atributos, metadatos y original.
3. **Investigation Workspace**: grafo y panel de evidencias en columnas;
   timeline cronológico, entidades observadas, alertas correlacionadas e
   historial. **Evaluar respuesta →** conserva el incidente investigado.
4. **Attack Replay**: activa el modo histórico y conserva el corte UTC en el
   panel lateral. Ejecuta detección hasta el corte y abre los incidentes
   transitorios en el mismo workspace.
5. **Response Center**: preselecciona el incidente investigado y muestra el
   motor de triage realmente devuelto por la API. Tipo de acción, objetivo,
   evidencia y confirmación explícita son obligatorios para registrar una
   simulación. Se muestran `mode=simulation` y `status=simulated`, sin atribuir
   efectos reales a su registro.

El dataset, el incidente y el modo temporal se mantienen en la sesión al cambiar
la navegación. El foco se recuerda por partición y corte; cambiar de dataset no
arrastra incidentes de otra partición. Los identificadores completos se muestran
en detalles técnicos. E001… y R001… son referencias visuales locales, no IDs de
la telemetría. Las entidades se extraen de atributos explícitos; aparecer en la
evidencia no demuestra que estén comprometidas.

## De una relación al archivo original

En el grafo, selecciona una relación R001… con ratón o teclado para consultar
su evidencia normalizada en el panel del dibujo. El selector nativo **Relación
a investigar** contiene las mismas referencias y nombres humanos; actualiza
el panel exterior **Evento de evidencia**. Las líneas continuas representan
relaciones observadas y las discontinuas asociaciones derivadas.

En **Archivo original**, **Cargar archivo original** llama a
`GET /v1/events/{event_id}/raw` con la partición seleccionada. Después,
**Descargar archivo original** entrega los bytes exactos recibidos. El archivo
puede contener varios registros; `source_record_number` identifica el registro
lógico del evento, desde 1. No se reconstruyen ni recortan bytes como si fueran
un registro original. Si ese número no existe, se indica como no disponible.
La pestaña **Identificadores y origen** conserva IDs, fecha literal y `raw_ref`.

## Replay y frescura

Cada página de eventos y cada consulta de grafo histórico envía `as_of`.
La consola descarta eventos posteriores al corte y relaciones cuya evidencia
no es visible. Los hallazgos históricos solo proceden de la respuesta de
una detección con `persisted=false`; no se leen colecciones ni detalles
persistidos en ese modo. Triage y respuesta están desactivados. El archivo
original también está desactivado: un archivo completo podría incluir registros
posteriores al corte. Los eventos normalizados siguen disponibles.

Los eventos se conservan 60 segundos en memoria de la sesión, separados por
API, partición y corte. **Actualizar datos** fuerza la consulta y una detección
refresca antes los eventos. La consola indica hora de carga y si utiliza API
o memoria; no afirma que el caché sea una conexión de salud en tiempo real.
Se muestra la fecha local de la última ejecución de detección. Si el conjunto
de eventos cambia después, se avisa que los hallazgos requieren otra detección;
refrescar eventos no ejecuta reglas automáticamente.

## Limitaciones de Streamlit

- Los widgets provocan una ejecución de Python; las pestañas se construyen
  juntas. El grafo no consulta la API mientras no se abre el workspace.
- El iframe es autónomo y no sincroniza sus clics con `session_state`. Permite
  consultar evidencia normalizada dentro del propio dibujo; el selector nativo
  equivalente controla el panel exterior y la descarga original. Se evita un
  puente JavaScript privado que dependa de detalles internos de Streamlit.
- El grafo funciona offline, con zoom, arrastre, controles de desplazamiento y
   nodos/relaciones activables con Tab y Enter/Espacio. La disposición relacional
   usa NetworkX ya instalado y una semilla fija para posicionar únicamente los
   nodos y conexiones devueltos por la API; no crea relaciones adicionales.
   R001… aparece en foco, selección o hover para evitar solapes; el nombre
   completo está disponible mediante accesibilidad y el selector nativo.
   Las relaciones también
  se pueden recorrer en un selector nativo. Su dibujo tiene límite de 120 nodos
  y 800 relaciones; la API informa truncamiento y limitaciones.
- No se implementan paneles acoplables, atajos globales ni arrastre entre
  paneles. En pantallas estrechas las tablas requieren desplazamiento interno;
  una investigación extensa se beneficia de un monitor de escritorio.
- La primera carga recorre todas las páginas de eventos. La búsqueda se realiza
  sobre ese snapshot en memoria; para grandes volúmenes harán falta búsqueda y
  paginación de servidor. Los originales descargados se guardan en la sesión.
- La API no enumera datasets ni envía notificaciones de nueva ingesta. El
  identificador se introduce manualmente y la detección actual es la última
  ejecutada para esa partición en la sesión. No se inventan totales globales.
- La evaluación es una valoración, no un hecho de telemetría. Registrar una
  simulación no demuestra que la medida funcione ni que el recurso esté aislado.

## Ensayo de la demo

En una terminal ejecuta `bash scripts/run_demo.sh`. En otra:

```bash
.venv/bin/python -m scripts.load_demo --with-triage --with-simulation
```

Abre la consola, selecciona **Sintético**, introduce `gsec-synthetic-30d-v1`
y pulsa **Ejecutar detección**. El fixture actual contiene 184 eventos,
tres alertas y un incidente. Abre **Investigar →**, selecciona una relación,
consulta sus eventos y descarga el archivo completo. Abre Response Center para
consultar triage e historial; registrar una nueva acción exige la confirmación.

En Attack Replay elige `13/10/2026 17:05:00` UTC, ejecuta detección hasta el
corte e investiga el resultado. Repite a `17:11:00` UTC: los resultados son
transitorios y no modifican los actuales. Desactiva **Reproducción histórica**
para volver al snapshot actual. Si cambias el puerto, usa `GSEC_DEMO_API_PORT`
y pasa al cargador `--api-url` con la URL indicada por el script.
