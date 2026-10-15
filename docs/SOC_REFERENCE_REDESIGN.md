# Rediseño a partir de template_example

## Corrección del enfoque anterior

La primera iteración cambió navegación y funcionalidades de investigación,
pero mantuvo la composición predeterminada de Streamlit. El usuario solicita
una similitud visual reconocible con las tres imágenes locales. Esta iteración
usa esas imágenes como referencia de composición y componentes.

| Referencia inspeccionada | Patrón adoptado | Datos usados |
| --- | --- | --- |
| `template_example/idea.png` | Navegación lateral, paneles delimitados, métricas agrupadas, inventario y cola | Eventos, alertas, incidentes y entidades explícitas recibidos de la API |
| `template_example/idea2.png` | Grafo protagonista con inspector lateral, controles discretos y conexiones teal | Grafo real y eventos que justifican cada relación |
| `template_example/idea3.png` | Barra de contexto, KPIs compactos, cabeceras técnicas y feed operativo | Severidad devuelta por detección y cronología del snapshot consultado |

Las referencias contienen indicadores MITRE, SLA, riesgo agregado, predicciones
y estados en directo que la API no proporciona. Su presencia en una captura
no autoriza a presentarlos como información real de Sentinel.

## Skills aplicadas

- **UI/UX Pro Max:** consulta local de estilo `cybersecurity operations dense dashboard`:
  resultado verificado `Data-Dense Dashboard`; padding compacto, tablas legibles,
  límites de densidad y alternativa accesible a gráficos. El resultado HUD
  cinematográfico no se adopta.
- **Design System:** arquitectura de tokens primitivos → semánticos → componentes;
  especificaciones de tarjetas, botones, estados y tablas.
- **UI Styling:** jerarquía visual, superficies consistentes, espaciado y estados
  accesibles. Sus ejemplos React/Tailwind se traducen a HTML/CSS propio y widgets
  Streamlit; no requieren migrar el stack ni instalar esas librerías.
- **Design:** enrutamiento a Design System y UI Styling para este tipo de trabajo.

## Sistema visual

Fondo `#0B0F15`, rail `#101721`, superficie `#141B25`, borde decorativo
`#293442`, texto `#E4EAF2` y acento teal `#46C8BA`. Rojo y ámbar acompañan
estados de riesgo o error. Tipografía sans local y valores técnicos mono.
La densidad de escritorio usa base 14 px y escala 4/8/12/16/24 px; los controles
mantienen etiquetas visibles y foco por teclado. El borde tenue de una tarjeta
es decorativo y no sustituye el indicador de foco de un control.

Barra superior compacta para dataset, vista temporal y última consulta. Las
explicaciones de procedencia y las fechas detalladas pasan a desplegables; el
origen sintético permanece visible. El overview organiza tarjetas y paneles con
prioridad para la cola de alertas, distribución, volumen temporal y entidades.
El workspace sitúa el grafo y su inspector antes de los detalles secundarios.

## Mantenibilidad y seguridad

Los componentes HTML usan clases propias y escapan el contenido procedente de
telemetría. Los widgets conservan controles nativos de Streamlit. El CSS se
acota a contenedores con claves `soc-*`: `st.container(key=...)` documenta su
clase `st-key-*`. Se evitan selectores `data-testid` y clases generadas de Emotion.
Los SVG de datos usan texto escapado o payload inerte; no se interpolan scripts
desde los eventos. Sin dependencias nuevas, escrituras en backend ni cambios
de contratos.

## Validación y revisión

Se comprobarán tanto los flujos existentes como la similitud visual en navegador
con datos sintéticos reales de la API. Las pruebas del primer rediseño que
dependían de métricas nativas se adaptarán a las tarjetas sin debilitar las
comprobaciones de partición, replay, evidencia original o confirmación.
La auditoría final corresponde a `soc_reviewer`, sin editar archivos.

## Significado de cada panel

| Panel | Alcance de los datos | Cuando faltan datos |
| --- | --- | --- |
| Eventos consultados | Eventos de la partición y corte que devolvió la API | Cero; sin actividad inventada |
| Alertas / Incidentes / Alta-crítica | Hallazgos de la última detección de esta vista, con evidencia visible | Cero no equivale a ausencia garantizada de ataque |
| Distribución de severidad | Conteo de las severidades devueltas por la detección | Anillo vacío y leyenda cero |
| Volumen diario | Barras de conteos observados por día UTC | No se interpola actividad entre fechas |
| Entidades observadas | Valores únicos presentes en atributos explícitos | Cero por tipo; no se inventa IP, archivo ni compromiso |
| Cola de investigación | Alertas de la vista y vínculo al incidente asociado | Estado vacío con siguiente paso operativo |
| Últimos eventos del snapshot | Registros recientes del dataset, no necesariamente relacionados con el ataque | Estado vacío; no se presenta como feed en directo |
| Grafo / Inspector | Incidente seleccionado y evidencia que justifica cada relación | Cobertura y límites explícitos; atributos ausentes no se rellenan |
| Triage / Respuesta | Evaluación y registro de simulación devueltos por la API | Sin valoración ni eficacia simulada inventadas |

El replay limita toda evidencia normalizada al corte. La descarga del archivo
completo, el triage persistido y la simulación quedan fuera de esa vista.
Cambiar de dataset invalida el incidente de otra partición. Consultar eventos
nuevos no recalcula automáticamente las detecciones: se muestra aviso de
hallazgos pendientes de actualizar.

## Resultado y comprobaciones

Capturas reales con datos sintéticos de la API:
[Overview](ui-preview/reference-overview.png),
[Workspace](ui-preview/reference-workspace.png),
[Grafo](ui-preview/reference-graph.png),
[Móvil](ui-preview/reference-mobile.png) y
[Menú móvil abierto](ui-preview/reference-mobile-menu.png).

En escritorio de 1600 px, la barra mide 64 px, las tarjetas KPI terminan a
249 px y la cola comienza a 536 px: el contenido operativo aparece en el
primer viewport. Grafo e inspector comienzan a 255 px con anchos 801/397 px.
Las etiquetas del grafo se midieron en 12 px efectivos. Se verificaron selección
de relación por teclado, evidencia normalizada, desplazamiento del grafo y las
cinco secciones. En sesión móvil de 375 px, el menú abre y cierra sin recorte;
el documento mantiene ancho 375 px. No se detectaron errores JavaScript.

Se corrigió un fallo que las pruebas de datos no detectaban: Streamlit elimina
SVG inline en `st.html`. Los iconos y el anillo se sirven ahora como imágenes
SVG propias, inertes y codificadas, con descripción alternativa. Se verificó
que el navegador las carga. La disposición relacional usa NetworkX ya instalado
y separa nodos en investigaciones pequeñas. Los grafos densos siguen necesitando
filtros y zoom.

Las pruebas verifican conteos reales, deduplicación de entidades explícitas,
datos ausentes, texto API escapado, navegación, evidencia original byte a byte,
replay transitorio y confirmación de simulaciones. Backend y contratos no han
cambiado en esta corrección visual. Sin dependencias nuevas, commit ni push.

Validación final: `.venv/bin/python -m pytest -q` → **83 passed**;
`git diff --check` limpio. `soc_reviewer` cerró la auditoría funcional y visual
sin bloqueadores abiertos, incluidas las capturas del menú móvil abierto/cerrado
y el aviso visible de detección pendiente.

## Acabado del grafo

El grafo comparte la estética de la consola: lienzo de 440 px con cuadrícula
tenue, iconos vectoriales, etiquetas de 13 px efectivos con fondo y nombres en
varias líneas. La selección resalta relaciones, extremos y vecinos; la leyenda
identifica relaciones observadas y derivadas. Los identificadores técnicos y
el JSON completo se consultan en desplegables. No se modifican los datos ni
las relaciones de la API.

[Captura final del grafo](ui-preview/graph-final.png) y
[Workspace actualizado](ui-preview/workspace-graph-final.png).
Validación: 22 pruebas frontend/API/grafo pasadas, comprobación de las tres
disposiciones en navegador, teclado, evidencia y desplazamiento sin errores
JavaScript. Auditoría final de `soc_reviewer` favorable.
