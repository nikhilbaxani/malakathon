# Dataset local inventado

`synthetic_30d.jsonl` contiene **184 eventos** en una ventana de 30 días:
180 controles benignos y cuatro eventos de una secuencia ficticia de escalada,
transferencias externas y borrado de copia de seguridad. No representa el
formato ni el contenido de ningún dataset oficial. Las etiquetas están separadas
en `ground_truth.json`, enlazadas mediante `id` del evento de origen.

La verdad terreno define tres alertas esperadas con regla, IDs de evidencia,
inicio de la secuencia y primer instante en que la evidencia basta para activar
la regla. Los controles benignos incluyen cambios de privilegio denegados,
transferencias bajo umbral o internas y operaciones de servicio fallidas.

Para regenerar y evaluar sin servidor:

```bash
.venv/bin/python -m scripts.generate_demo_dataset
.venv/bin/python -m scripts.evaluate_demo
```

La evaluación compara exactamente `(rule_id, conjunto de IDs de origen)` para
contar verdaderos positivos, falsos positivos y falsos negativos. Calcula el
**tiempo hasta detección en tiempo de evento** ejecutando la regla en cortes
sucesivos desde el inicio etiquetado. No mide latencia de ingesta en vivo ni
calidad sobre telemetría oficial. La muestra fue diseñada para las reglas
actuales y sus cifras no estiman rendimiento en producción.

Para verla en la consola, inicia los servicios en la primera terminal:

```bash
bash scripts/run_demo.sh
```

En una segunda terminal, carga el fixture:

```bash
.venv/bin/python -m scripts.load_demo --with-triage --with-simulation
```

En Streamlit selecciona `Sintético`, escribe `gsec-synthetic-30d-v1` y pulsa
`Ejecutar detección`. La segunda ejecución es idempotente para alertas e
incidentes. El cargador también reutiliza el triage y la simulación de demo
si ya existen para ese incidente. Cada arranque crea un almacén aislado bajo
`data/demo_runs/`; sus bytes y logs quedan disponibles tras detener los
servidores y Git los ignora. Las acciones desde la consola siguen siendo
operaciones explícitas y pueden registrar nuevas evaluaciones o simulaciones.

## Attack Graph forense

Tras cargar la demo y ejecutar la detección en la consola, abre la pestaña
`Attack Graph` y selecciona el único incidente. El gráfico permite ampliar,
desplazar, filtrar tipos de nodo y pulsar nodos o aristas. Debajo del gráfico,
`Relación` muestra los IDs de eventos que sustentan cada vínculo; `Ver evento
de evidencia` abre el registro normalizado. La pestaña `Eventos` permite
inspeccionar el mismo ID y su referencia al archivo original. Las aristas de
alerta e incidente se marcan como derivadas; las demás se limitan a campos
explícitos de los eventos.

Para probar el replay, activa `Reproducción histórica` en la barra lateral,
elige **13/10/2026 17:05:00 UTC** y pulsa `Ejecutar detección hasta el corte`.
Selecciona el incidente transitorio en `Attack Graph`: solo aparecen relaciones
respaldadas por eventos hasta ese instante. Cambia a **17:11:00 UTC** y vuelve
a ejecutar la detección para ver la secuencia completa. El replay no modifica
los incidentes, el triage ni las simulaciones persistidas. También se puede
consultar el JSON del grafo con la API, siempre con la partición explícita:

```bash
curl -s 'http://127.0.0.1:8000/v1/incidents?dataset_kind=synthetic&dataset_id=gsec-synthetic-30d-v1'
```

El fixture actual identifica usuario y host, pero no contiene direcciones IP,
rutas de archivo ni procesos. El grafo de esta demo es deliberadamente parcial:
no atribuye una IP externa a las transferencias ni inventa un archivo borrado.
