# GSEC Sentinel: auditoría UX y sistema de interacción

Fecha: 15 de octubre de 2026. Alcance: frontend Streamlit existente.

La dirección visual inicial de este documento fue sustituida por el
[rediseño basado en template_example](SOC_REFERENCE_REDESIGN.md), que recoge
la corrección del usuario, las referencias gráficas y el sistema visual actual.
Las garantías de evidencia, partición, replay y simulación descritas aquí siguen
vigentes.

## Auditoría antes de implementar

Inspección de `frontend/app.py`, `api.py`, `graph.py`, `replay.py`, contratos,
rutas FastAPI y pruebas. Capacidades comprobadas: búsqueda de eventos, detección,
alertas, incidentes, triage, grafo con evidencia, replay UTC transitorio y registro
de simulaciones. No existe evaluación del impacto real de una contención.

| Hallazgo | Efecto operativo | Decisión |
| --- | --- | --- |
| Grafo y cronología en pantallas distintas | Investigación fragmentada | Workspace con grafo, relaciones, cronología y evidencia |
| Selector independiente en respuesta | Repetición de selección | Mantener incidente dentro de la partición |
| IDs largos y JSON siempre visibles | Lectura lenta de entidades y hallazgos | Etiquetas humanas; IDs y JSON en detalles |
| Solo `raw_ref` en evidencia | No se puede consultar el original desde consola | Recuperar bytes por endpoint API existente, bajo petición |
| Grafo dependiente del ratón | Barreras para teclado y relaciones pequeñas | Selección equivalente nativa y controles de teclado |
| Colores arbitrarios por entidad | Rojo/ámbar pierden significado | Reservarlos a riesgo/advertencias; texto por tipo y relación |
| Caché y hallazgos con frescura distinta | Puede confundirse consulta reciente con nueva detección | Fecha de consulta y alcance de ejecución explícitos |
| CSS con `data-testid` internos | Mantenimiento frágil | Tema nativo y estilos solo del HTML propio |

La presencia de una entidad no prueba compromiso. Los conteos representan
únicamente respuestas API de la partición y ejecución visibles. La clasificación
sintético/oficial procede del contexto de consulta; no certifica autenticidad.

## Uso de UI/UX Pro Max

Skill local: `.agents/skills/ui-ux-pro-max/SKILL.md`.

Consultas ejecutadas:

```bash
python3 .agents/skills/ui-ux-pro-max/scripts/search.py 'security operations dashboard dense dark' --design-system --density 9 -p 'GSEC Sentinel' -f markdown
python3 .agents/skills/ui-ux-pro-max/scripts/search.py 'data dense dashboard' --domain style -n 2
python3 .agents/skills/ui-ux-pro-max/scripts/search.py 'drill down evidence' --domain chart -n 2
```

El generador sugirió Enterprise Gateway y contenido comercial, descartados por
incompatibilidad con el producto. La búsqueda específica verificó
**Data-Dense Dashboard**: paneles compactos, filas de 36 px, tablas ordenables,
carga explícita y foco visible. La consulta de gráficos aporta selección por
teclado y una alternativa tabular; su árbol de descomposición no corresponde al
grafo forense y no se adopta. Streamlit no figura entre los stacks de la skill;
se usan sus reglas web y las APIs nativas disponibles en el entorno.

## Sistema visual

| Token | Valor | Uso |
| --- | --- | --- |
| Fondo | `#0B1220` | Charcoal, lienzo de trabajo |
| Superficie | `#132235` | Navy, paneles y controles |
| Texto | `#E6EDF5` | Texto principal |
| Texto secundario | `#A7B6C8` | Contexto legible |
| Acento | `#67E8F9` | Cyan, selección y controles |
| Riesgo | `#F87171` | Fallo o severidad alta/crítica con etiqueta |
| Advertencia | `#FBBF24` | Severidad media, truncamiento y límites con etiqueta |

Tipografía sans local; números tabulares y código monoespaciado en detalles.
Escala de espaciado 4/8/12/16/24 px; encabezados discretos, componentes nativos,
sin fuentes externas ni animaciones decorativas. La densidad favorece escritorio;
las tablas extensas mantienen desplazamiento horizontal interno.

Contraste calculado con luminancia relativa WCAG sobre ambas superficies:
texto principal 13,61:1 o superior; secundario 7,77:1 o superior; cyan 11,08:1
o superior; rojo 5,80:1 o superior; ámbar 9,62:1 o superior. Estos resultados
validan los pares de tokens; no constituyen una auditoría de accesibilidad del
DOM completo de Streamlit.

## Arquitectura de información

1. **SOC Overview:** conteos verificables, severidades, estados y alertas con
   acceso directo al incidente asociado.
2. **Threat Hunting:** filtros, búsqueda, eventos y consulta de evidencia.
3. **Investigation Workspace:** incidente, grafo, entidades observadas,
   relaciones, cronología, alertas correlacionadas y evidencia original.
4. **Attack Replay:** selección de corte UTC y reconstrucción transitoria,
   con contexto histórico visible. Sin triage ni simulación histórica.
5. **Response Center:** evaluación devuelta por la API, objetivo, evidencia,
   confirmación explícita y resultado del registro de simulación.

El contexto incluye origen y nombre del dataset, incidente y corte. Al cambiar
partición se invalida la selección que ya no pertenece a ella. Un corte nuevo
requiere detección nueva; no se presentan resultados de otro corte.

## Flujos de investigación

Detectar → elegir alerta → abrir incidente → seleccionar relación → inspeccionar
eventos que la justifican → consultar atributos y procedencia → recuperar archivo
original. El archivo bruto es completo e inmutable; `source_record_number` señala
el registro lógico. No se presenta un JSON normalizado como si fuera el original.

Investigar → reconstruir a un corte → consultar solo evidencia visible. Los bytes
del archivo completo pueden contener eventos posteriores; su recuperación queda
deshabilitada en replay para preservar el límite temporal.

Investigar → Response Center → revisar evaluación → indicar acción y objetivo →
seleccionar evidencia → confirmar simulación → consultar `mode` y `status`.
`simulated` significa registro aceptado; no demuestra aislamiento, prevención ni
impacto sobre sistemas. No se inventan métricas de eficacia.

## Estados y límites

Carga con indicador nativo; vacío con siguiente paso concreto; errores de API
con reintento; fecha de consulta y antigüedad sin afirmar conexión continua.
Las conclusiones de triage muestran el motor realmente devuelto por la API.
Rojo/ámbar acompañados de texto, relaciones observadas/derivadas etiquetadas.

Streamlit ejecuta de nuevo el script tras las interacciones. El iframe HTML del
grafo tiene estado propio: su clic no cambia automáticamente el selector Python.
Las relaciones numeradas y el selector accesible proporcionan la ruta al mismo
evento sin un componente bidireccional adicional. La selección no se comparte
entre navegadores ni sobrevive necesariamente al cierre de sesión.

La API no ofrece catálogo de datasets: se introduce el identificador existente.
Los eventos se recorren por páginas y se mantienen en memoria; el límite visual
de 120 nodos no limita el coste de construir el grafo en backend. Para volúmenes
grandes se requieren consultas de servidor adicionales, fuera de este rediseño.
No hay actualización continua ni slider de reproducción que reproduzca estados
persistidos: el replay recalcula una vista hasta un instante.

## Validación realizada

Suite completa: `.venv/bin/python -m pytest -q` → **80 passed**.
Después del ajuste de legibilidad del grafo, pruebas focalizadas frontend,
grafo y recorrido API: **22 passed**. `git diff --check` sin errores.

Streamlit AppTest y flujo integrado contra FastAPI ASGI con DuckDB y originales
temporales verifican navegación, relación/evidencia/original, aislamiento de
particiones, corte temporal, confirmación y persistencia de simulación. El
archivo recuperado desde la consola se compara byte a byte con el ingestado.
La prueba comprueba que el replay no modifica incidente, triage ni acciones.

Comprobación adicional con Playwright y Brave headless, usando FastAPI y
Streamlit reales en puertos locales aislados y otro DuckDB temporal, con fixture
de 184 eventos sintéticos. Se recorren las cinco secciones, se activa una
relación del SVG con Enter, se consulta su evidencia normalizada y se prueban
controles de desplazamiento. Tamaños efectivos medidos: etiquetas de nodo
12 px y referencias de relación 13 px en columna de escritorio. Viewport móvil
375 px: sin desbordamiento horizontal de la página. Sin errores JavaScript.
Esto no certifica accesibilidad completa ni sustituye pruebas con lectores
de pantalla. El caso móvil comprobó la disposición y navegación básica; el
recorrido de investigación completo se verificó en escritorio y AppTest.

Capturas reales del fixture sintético: [Overview](ui-preview/soc-overview.png),
[Workspace](ui-preview/investigation-workspace.png),
[Grafo](ui-preview/investigation-graph.png) y
[Viewport de 375 px](ui-preview/mobile-375.png). Son estados de la sesión de
prueba, no una maqueta ni métricas globales. En grafos densos pueden solaparse
etiquetas; los filtros, zoom y selector de relaciones permiten inspeccionarlas.
Se usa `st.iframe` cuando está disponible y el renderer anterior como fallback.

Auditoría independiente final de `soc_reviewer`, sin editar: no se identificaron
bloqueadores P0/P1. Sus hallazgos sobre referencias E del subconjunto, contexto
inicial y texto de replay se corrigieron y verificaron. La revisión visual añadió
la compensación de tamaño SVG y corrigió el arranque documentado a
`.venv/bin/python -m streamlit run frontend/app.py` desde la raíz.

Archivos del rediseño: `frontend/app.py`, `frontend/api.py`,
`frontend/graph.py`, `frontend/presentation.py`, `frontend/README.md`,
`.streamlit/config.toml`, `tests/test_frontend.py`, `tests/test_api_flow.py`
y este documento. Backend y contratos conservados; cambios locales anteriores
preservados. Sin commit ni push.
