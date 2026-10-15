"""SOC console. From repo root: .venv/bin/python -m streamlit run frontend/app.py"""

from __future__ import annotations

import os
from collections import Counter
import time
from datetime import date, datetime, timezone
from typing import Any

import streamlit as st
import streamlit.components.v1 as components

from frontend import visual
from frontend.api import ApiError, SocApi
from frontend.graph import MAX_NODES, graph_view, missing_optional_types, render_graph_html
from frontend.replay import detection_results_until, events_until, parse_utc
from frontend.presentation import event_label, event_rows, entity_rows, relation_label, severity_label


PAGES = ("SOC Overview", "Threat Hunting", "Investigation Workspace", "Attack Replay", "Response Center")
EVENT_CACHE_SECONDS = 60


def _navigate(page: str) -> None:
    st.session_state["nav"] = page
    if page == "Attack Replay":
        st.session_state["replay_mode"] = True


def _nav_changed() -> None:
    if st.session_state.get("nav") == "Attack Replay":
        st.session_state["replay_mode"] = True


def _fetch_events(api: SocApi, kind: str, dataset_id: str, as_of: datetime | None, *, force: bool = False) -> list[dict[str, Any]]:
    cache = st.session_state.setdefault("event_cache", {})
    key = (api.base_url, kind, dataset_id, as_of.isoformat() if as_of else None)
    cached = cache.get(key)
    if force or cached is None or time.monotonic() - cached[0] >= EVENT_CACHE_SECONDS:
        with st.spinner("Cargando eventos de la API…"):
            events = api.all_events(kind, dataset_id, as_of=as_of)
        if as_of is not None:
            events = events_until(events, as_of)
        loaded_at = datetime.now(timezone.utc)
        cache[key] = (time.monotonic(), loaded_at, events)
        st.session_state["event_cache_status"] = (loaded_at, True)
        return events
    st.session_state["event_cache_status"] = (cached[1], False)
    return cached[2]


def _focus_incident(incident_id: str) -> None:
    st.session_state["selected_incident"] = incident_id
    st.session_state["nav"] = "Investigation Workspace"


def _picker_changed(key: str) -> None:
    selected = st.session_state.get(key)
    st.session_state["selected_incident"] = None if selected == "— Selecciona un incidente —" else selected


def _sync_incident(incidents: list[dict[str, Any]], partition_key: tuple[str, str, str | None]) -> None:
    ids = {incident["incident_id"] for incident in incidents}
    previous = st.session_state.get("incident_partition")
    remembered = st.session_state.setdefault("incident_contexts", {})
    if previous != partition_key:
        if previous:
            remembered[previous] = st.session_state.get("selected_incident")
        st.session_state["incident_partition"] = partition_key
        st.session_state["selected_incident"] = remembered.get(partition_key)
        st.session_state["response_incident"] = "— Selecciona un incidente —"
    if st.session_state.get("selected_incident") not in ids:
        st.session_state["selected_incident"] = None


def _incident_picker(incidents: list[dict[str, Any]], *, key: str) -> str | None:
    ids = [incident["incident_id"] for incident in incidents]
    if not ids:
        st.info("No hay incidentes en esta vista. Ejecuta la detección para investigar.")
        return None
    selected = st.session_state.get("selected_incident")
    if selected not in ids:
        selected = ids[0]
    if st.session_state.get(key) != selected:
        st.session_state[key] = selected
    labels = {item["incident_id"]: f"{index + 1:02d} · {item['title']} · {item['status']}"
              for index, item in enumerate(incidents)}
    chosen = st.selectbox("Incidente en investigación", ids, key=key, format_func=labels.get,
                          on_change=_picker_changed, args=(key,))
    st.session_state["selected_incident"] = chosen
    return chosen


def _dataframe(rows: list[dict[str, Any]], *, height: int | str = "auto") -> None:
    if not rows:
        st.caption("Sin registros para esta vista.")
        return
    st.dataframe(rows, width="stretch", hide_index=True, row_height=36, height=height)


def _evidence_panel(
    api: SocApi, events: list[dict[str, Any]], kind: str, dataset_id: str,
    *, key: str, replay: bool = False,
    event_indexes: dict[str, int] | None = None,
) -> None:
    visual.panel_heading("Evidence inspector", "EVENTOS VERIFICABLES")
    if not events:
        st.info("No hay eventos de evidencia visibles para esta selección.")
        return
    ordered = sorted(events, key=lambda item: (parse_utc(item["timestamp_utc"]), item["event_id"]))
    event_ids = [event["event_id"] for event in ordered]
    labels = {event["event_id"]: event_label(event, (event_indexes or {}).get(event["event_id"], index))
              for index, event in enumerate(ordered)}
    event_id = st.selectbox("Evento de evidencia", event_ids, key=key, format_func=labels.get)
    event = next(item for item in ordered if item["event_id"] == event_id)
    visual.evidence_header(event)
    normalized, original, metadata = st.tabs(["Normalizado", "Archivo original", "Identificadores y origen"])
    with normalized:
        attrs = event.get("attributes", {})
        if attrs:
            visual.attributes_summary(attrs)
        else:
            st.caption("El evento no contiene atributos adicionales.")
        with st.expander("Evento normalizado completo"):
            st.json(event)
    with original:
        st.caption("La API devuelve los bytes del archivo completo sin transformar. Puede contener varios registros.")
        record_number = event.get("source_record_number")
        st.write(f"Registro lógico de este evento: {record_number if record_number is not None else 'No disponible'}")
        if replay:
            st.info("Archivo original desactivado en replay: el archivo completo puede contener registros posteriores al corte. El evento normalizado sí respeta el corte.")
        else:
            raw_key = (api.base_url, kind, dataset_id, event_id)
            raw_cache = st.session_state.setdefault("raw_files", {})
            if st.button("Cargar archivo original", key=f"raw_{key}_{event_id}"):
                try:
                    with st.spinner("Recuperando bytes originales de la API…"):
                        raw_cache[raw_key] = api.raw_event(event_id, kind, dataset_id)
                except (ApiError, ValueError, TypeError) as exc:
                    st.error(f"No se pudo recuperar el original. Reintenta con Cargar archivo original: {exc}")
            if raw_key in raw_cache:
                st.download_button("Descargar archivo original", raw_cache[raw_key],
                                   file_name="telemetria-original.bin", mime="application/octet-stream",
                                   key=f"download_{key}_{event_id}")
                st.caption(f"{len(raw_cache[raw_key]):,} bytes exactos recibidos de la API. No se recortan ni se reconstruyen registros.")
    with metadata:
        st.json({field: event.get(field) for field in (
            "event_id", "source_event_id", "source_timestamp", "timestamp_utc", "raw_ref",
            "source_record_number", "dataset_kind", "dataset_id",
        )})


def _event_explorer(api: SocApi, events: list[dict[str, Any]], kind: str, dataset_id: str, replay: bool) -> None:
    visual.panel_heading("Explorador de telemetría", f"{len(events):,} EVENTOS")
    types = sorted({str(event.get("event_type", "")) for event in events})
    sources = sorted({str(event.get("source", "")) for event in events})
    first, second, third = st.columns([1, 1, 2])
    selected_type = first.selectbox("Tipo de evento", ["Todos", *types])
    selected_source = second.selectbox("Origen", ["Todos", *sources])
    search = third.text_input("Buscar ID, usuario, host o atributos")
    shown = [event for event in events
             if (selected_type == "Todos" or event.get("event_type") == selected_type)
             and (selected_source == "Todos" or event.get("source") == selected_source)
             and (not search or search.casefold() in str(event).casefold())]
    st.caption(f"{len(shown):,} de {len(events):,} eventos coinciden. Las referencias E son locales a esta vista.")
    if not shown:
        st.info("No hay eventos con estos filtros. Amplía el tipo, el origen o el texto de búsqueda.")
        return
    _dataframe(event_rows(shown), height=360)
    _evidence_panel(api, shown, kind, dataset_id, key="hunt_evidence", replay=replay)


def _alerts(alerts: list[dict[str, Any]], incident_by_alert: dict[str, str] | None = None) -> None:
    if not alerts:
        st.info("Sin alertas en esta selección.")
        return
    _dataframe([{"Riesgo": severity_label(item["severity"]), "Alerta": item["title"],
                 "UTC": item.get("detected_at", ""), "Regla": item["rule_id"],
                 "Evidencias": len(item.get("evidence_event_ids", []))} for item in alerts])
    for alert in alerts:
        with st.expander(f"{severity_label(alert['severity'])} · {alert['title']}"):
            st.write(alert.get("description", ""))
            st.json({"alert_id": alert["alert_id"], "evidence_event_ids": alert.get("evidence_event_ids", [])})
            incident_id = (incident_by_alert or {}).get(alert["alert_id"])
            if incident_id:
                st.button("Investigar alerta →", key=f"all_investigate_{alert['alert_id']}",
                          on_click=_focus_incident, args=(incident_id,))


def _response_center(api: SocApi, incidents: list[dict[str, Any]], kind: str, dataset_id: str, replay: bool) -> None:
    visual.panel_heading("Evaluación y respuesta", "SIMULACIÓN")
    st.caption("Las acciones registradas no ejecutan contención en sistemas externos.")
    if replay:
        st.info("Vuelve a la vista actual para evaluar triage o registrar una simulación.")
        return
    if not incidents:
        st.info("Ejecuta la detección para seleccionar un incidente.")
        return
    options = ["— Selecciona un incidente —", *[item["incident_id"] for item in incidents]]
    focused = st.session_state.get("selected_incident")
    if focused in options and st.session_state.get("response_incident") != focused:
        st.session_state["response_incident"] = focused
    selected = st.selectbox("Seleccionar incidente para respuesta", options, key="response_incident",
                            format_func=lambda value: next((f"{item['title']} · {item['status']}" for item in incidents if item["incident_id"] == value), value),
                            on_change=_picker_changed, args=("response_incident",))
    if selected == options[0]:
        st.info("Selecciona explícitamente un incidente antes de evaluar o simular una respuesta.")
        return
    st.session_state["selected_incident"] = selected
    try:
        detail = api.incident_detail(selected, kind, dataset_id)
    except (ApiError, ValueError, KeyError, TypeError) as exc:
        st.error(f"No se pudo cargar el incidente: {exc}")
        return
    incident = detail["incident"]
    evidence = incident.get("evidence_event_ids", [])
    st.caption(f"{incident['title']} · estado {incident['status']} · {len(evidence)} eventos de evidencia")
    notice = st.session_state.pop("response_notice", None)
    if notice and notice[0] == (kind, dataset_id, selected):
        st.success(notice[1])
    st.markdown("**Evaluaciones existentes**")
    if not detail.get("triage_results"):
        st.caption("Sin triage registrado.")
    for result in detail.get("triage_results", []):
        with st.container(border=True):
            st.write(f"Motor: {result['engine']} · Evaluación: {result['assessment']}")
            st.write(result["summary"])
            st.caption(f"{len(result.get('evidence_event_ids', []))} eventos respaldan esta evaluación.")
            with st.expander("Detalles de la evaluación"):
                st.json(result)
    if st.button("Evaluar triage", key=f"triage_{selected}"):
        try:
            result = api.triage(selected, kind, dataset_id)
        except (ApiError, ValueError, KeyError, TypeError) as exc:
            st.error(f"No se registró triage: {exc}")
        else:
            st.session_state["response_notice"] = (
                (kind, dataset_id, selected),
                f"Triage registrado · motor {result['engine']} · evaluación {result['assessment']}",
            )
            st.rerun()
    st.markdown("**Simulaciones registradas**")
    if not detail.get("containment_actions"):
        st.caption("Sin acciones registradas.")
    for action in detail.get("containment_actions", []):
        st.write(f"{action['mode'].upper()} · {action['status']} · {action['action_type']} · {action['target']}")
    with st.form(f"simulation_{selected}"):
        st.markdown("**Preparar simulación**")
        action_type = st.text_input("Tipo de acción", placeholder="Ej.: isolate_host")
        target = st.text_input("Objetivo exacto", placeholder="Identificador del recurso")
        evidence_by_id = {event["event_id"]: event for event in detail.get("events", [])}
        chosen_evidence = st.multiselect("Evidencia que justifica la simulación", evidence,
                                       format_func=lambda value: event_label(evidence_by_id[value]) if value in evidence_by_id else "Evento de evidencia (ver detalles)")
        confirmed = st.checkbox("Confirmo que registraré solo una simulación para el incidente y objetivo indicados")
        submitted = st.form_submit_button("Registrar simulación", type="primary")
    if submitted:
        if not action_type.strip() or not target.strip() or not chosen_evidence or not confirmed:
            st.error("Indica tipo, objetivo y evidencia; confirma expresamente la simulación.")
            return
        try:
            result = api.simulate(selected, kind, dataset_id, action_type.strip(), target.strip(), chosen_evidence)
        except (ApiError, ValueError, KeyError, TypeError) as exc:
            st.error(f"La simulación no se registró: {exc}")
            return
        if result.get("mode") != "simulation" or result.get("status") != "simulated":
            st.warning(f"Respuesta de la API: mode={result.get('mode')}, status={result.get('status')}. No se confirmó una simulación completada.")
            return
        st.session_state["response_notice"] = (
            (kind, dataset_id, selected),
            f"API: mode={result['mode']} · status={result['status']}",
        )
        st.rerun()


def _graph_panel(
    api: SocApi, incident_id: str, evidence: list[dict[str, Any]], kind: str,
    dataset_id: str, as_of: datetime | None, incident: dict[str, Any], alerts: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    """Return events justifying the selected relation, without fetching persisted replay detail."""
    try:
        with st.spinner("Consultando grafo forense…"):
            graph = api.incident_graph(incident_id, kind, dataset_id, as_of=as_of, max_nodes=MAX_NODES)
        metadata = graph.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Metadatos de grafo inválidos")
        if metadata.get("dataset_kind") != kind or metadata.get("dataset_id") != dataset_id:
            raise ValueError("El grafo recibido no corresponde a la partición seleccionada")
        if as_of is not None and (not metadata.get("as_of") or parse_utc(metadata["as_of"]) != as_of):
            raise ValueError("El grafo histórico recibido no confirma el corte temporal")
        node_types = sorted({str(node.get("type", "OTRO")) for node in graph.get("nodes", []) if isinstance(node, dict)})
        with st.expander("Filtros y disposición del grafo"):
            chosen_types = st.multiselect("Tipos de entidad en el grafo", node_types, default=node_types)
            layout = st.selectbox("Disposición", ["Relacional", "Capas", "Circular"])
        visible_ids = {event["event_id"] for event in evidence}
        nodes, edges, ui_truncated = graph_view(graph, selected_types=set(chosen_types),
                                                visible_event_ids=visible_ids, as_of=as_of)
        ordered_events = sorted(evidence, key=lambda event: (parse_utc(event["timestamp_utc"]), event["event_id"]))
        event_names = {event["event_id"]: f"E{index + 1:03d} · {event['event_type']}" for index, event in enumerate(ordered_events)}
        alert_names = {alert["alert_id"]: alert["title"] for alert in alerts}
        display_nodes = []
        for node in nodes:
            label = node.get("label", "")
            node_type = str(node.get("type", "")).casefold()
            if node_type == "event":
                label = event_names.get(label, "Evento de evidencia")
            elif node_type == "alert":
                label = alert_names.get(label, "Alerta correlacionada")
            elif node_type == "incident":
                label = incident["title"]
            display_nodes.append({**node, "label": label, "source_label": node.get("label")})
        nodes = display_nodes
    except (ApiError, ValueError, KeyError, TypeError) as exc:
        st.error(f"Grafo no disponible: {exc}")
        st.caption("La cronología y la evidencia siguen disponibles. Pulsa Actualizar datos para reintentar.")
        return None
    visual.panel_heading("Attack graph", f"{len(nodes)} NODOS / {len(edges)} RELACIONES")
    if metadata.get("truncated") or ui_truncated:
        st.info("Vista parcial por límite de nodos o relaciones. Consulta los detalles de cobertura.")
    if metadata.get("limitations") or missing_optional_types(node_types):
        with st.expander("Cobertura y limitaciones del grafo"):
            for limitation in metadata.get("limitations", []):
                st.write(limitation)
            absent = missing_optional_types(node_types)
            if absent:
                st.caption("Entidades opcionales ausentes: " + ", ".join(absent))
    if not nodes:
        st.info("No hay relaciones visibles para este incidente y filtro.")
        return None
    graph_html = render_graph_html(nodes, edges, layout=layout, evidence=evidence)
    if hasattr(st, "iframe"):
        st.iframe(graph_html, height=700, alt="Grafo forense interactivo con relaciones y evidencia normalizada")
    else:
        components.html(graph_html, height=700, scrolling=True)
    st.caption("Continua = observada · discontinua = derivada. Selecciona una relación para abrir evidencia.")
    node_by_id = {node["id"]: node for node in nodes}
    if edges:
        edge_index = st.selectbox("Relación a investigar", list(range(len(edges))),
                                  format_func=lambda index: relation_label(index, edges[index], node_by_id))
        edge = edges[edge_index]
        st.write("Asociación derivada" if edge.get("basis") == "derived" else "Relación observada")
        st.caption(f"{len(edge.get('evidence_event_ids', []))} eventos de evidencia · {edge.get('time_start_utc', '')}")
        with st.expander("Proveniencia e identificadores de la relación"):
            st.json(edge)
        ids = set(edge.get("evidence_event_ids", []))
        return [event for event in evidence if event["event_id"] in ids]
    with st.expander("Inspeccionar entidades del grafo"):
        node_id = st.selectbox("Entidad", list(node_by_id), format_func=lambda value: str(node_by_id[value].get("label", value)))
        st.json(node_by_id[node_id])
    return None


def _investigation_workspace(
    api: SocApi, events: list[dict[str, Any]], alerts: list[dict[str, Any]], incidents: list[dict[str, Any]],
    kind: str, dataset_id: str, as_of: datetime | None,
) -> None:
    incident_id = _incident_picker(incidents, key="workspace_incident")
    if incident_id is None:
        st.markdown("**Cronología de eventos disponibles**")
        _dataframe(event_rows(events), height=300)
        return
    incident = next(item for item in incidents if item["incident_id"] == incident_id)
    visible_by_id = {event["event_id"]: event for event in events}
    evidence = [visible_by_id[event_id] for event_id in incident.get("evidence_event_ids", []) if event_id in visible_by_id]
    correlated = [alert for alert in alerts if alert["alert_id"] in incident.get("alert_ids", [])]
    detail = None
    if as_of is not None:
        st.caption("INVESTIGACIÓN HISTÓRICA · resultados transitorios hasta el corte; triage y respuesta desactivados.")
    else:
        try:
            detail = api.incident_detail(incident_id, kind, dataset_id)
            evidence = detail.get("events", evidence)
            correlated = detail.get("alerts", correlated)
        except (ApiError, ValueError, KeyError, TypeError) as exc:
            st.error(f"Detalle no disponible: {exc}")
    heading, action = st.columns([5, 1])
    with heading:
        visual.status_strip(incident["title"], len(evidence), len(correlated), historical=as_of is not None)
    action.button("Evaluar respuesta →", on_click=_navigate, args=("Response Center",), disabled=as_of is not None)
    graph_col, evidence_col = st.columns([2, 1], gap="small")
    with graph_col, st.container(key="soc-panel-graph"):
        related = _graph_panel(api, incident_id, evidence, kind, dataset_id, as_of, incident, correlated)
    with evidence_col, st.container(key="soc-panel-inspector"):
        event_indexes = {event["event_id"]: index for index, event in enumerate(sorted(
            evidence, key=lambda item: (parse_utc(item["timestamp_utc"]), item["event_id"]),
        ))}
        _evidence_panel(api, related if related is not None else evidence, kind, dataset_id,
                        key="workspace_evidence", replay=as_of is not None, event_indexes=event_indexes)
    chronology, entities, alert_tab, assessments = st.tabs(["Timeline cronológico", "Entidades observadas", "Alertas correlacionadas", "Triage e historial"])
    with chronology:
        st.caption("Orden por timestamp_utc de los eventos. Las referencias E son locales a la lista de evidencia.")
        _dataframe(event_rows(evidence), height=320)
    with entities:
        st.caption("Identificadas explícitamente en atributos de la evidencia. Su presencia no demuestra compromiso.")
        _dataframe(entity_rows(evidence))
    with alert_tab:
        _alerts(correlated)
    with assessments:
        if detail is None:
            st.info("Historial persistido no disponible en esta vista.")
        else:
            results = detail.get("triage_results", [])
            actions = detail.get("containment_actions", [])
            if not results and not actions:
                st.caption("Sin evaluaciones ni acciones registradas.")
            for result in results:
                st.write(f"{result['engine']} · {result['assessment']}")
                st.write(result["summary"])
                with st.expander("Detalles del triage"):
                    st.json(result)
            for record in actions:
                label = "SIMULACIÓN" if record.get("mode") == "simulation" else "ACCIÓN REAL REGISTRADA"
                st.write(f"{label} · {record['action_type']} · {record['target']} · {record['status']}")
            with st.expander("Identificadores del incidente"):
                st.json(incident)


def _attack_replay(events: list[dict[str, Any]], alerts: list[dict[str, Any]], incidents: list[dict[str, Any]], as_of: datetime | None) -> None:
    visual.panel_heading("Reconstrucción temporal", "CORTE UTC")
    if as_of is None:
        st.info("Activa Reproducción histórica y elige el corte UTC en el panel lateral.")
        return
    st.info(f"REPLAY hasta {as_of.isoformat()} · solo eventos anteriores o iguales al corte. Resultados transitorios.")
    st.caption("1. Ajusta fecha y hora UTC. 2. Ejecuta detección hasta el corte. 3. Abre el incidente para explorar su evidencia histórica.")
    first, second, third = st.columns(3)
    first.metric("Eventos hasta el corte", len(events))
    second.metric("Alertas del corte", len(alerts))
    third.metric("Incidentes del corte", len(incidents))
    for incident in incidents:
        title, action = st.columns([4, 1])
        title.write(incident["title"])
        title.caption(f"{len(incident.get('evidence_event_ids', []))} eventos sustentan este incidente histórico")
        action.button("Investigar →", key=f"replay_investigate_{incident['incident_id']}",
                      on_click=_focus_incident, args=(incident["incident_id"],))
    st.markdown("**Cronología visible hasta el corte**")
    _dataframe(event_rows(events), height=360)


def _overview(events: list[dict[str, Any]], alerts: list[dict[str, Any]], incidents: list[dict[str, Any]], replay: bool, as_of: datetime | None) -> None:
    visual.kpis(events, alerts, incidents)
    distribution, volume, entities = st.columns([1.2, 1.5, 1], gap="small")
    with distribution, st.container(key="soc-panel-severity"):
        visual.panel_heading("Distribución de alertas", "SEVERIDAD")
        visual.severity_distribution(alerts)
    with volume, st.container(key="soc-panel-volume"):
        visual.panel_heading("Volumen de telemetría", "EVENTOS / DÍA UTC")
        days = Counter(parse_utc(event["timestamp_utc"]).date() for event in events)
        if days:
            st.bar_chart([{"Día UTC": day, "Eventos": count} for day, count in sorted(days.items())],
                          x="Día UTC", y="Eventos", color="#46c8ba", height=190)
        else:
            st.caption("Sin eventos para representar.")
    with entities, st.container(key="soc-panel-entities"):
        visual.panel_heading("Entidades observadas")
        visual.entities_summary(events)
    queue, feed = st.columns([1.65, 1], gap="small")
    with queue, st.container(key="soc-panel-queue"):
        visual.panel_heading("Cola de investigación", f"{len(alerts)} ALERTAS")
        if not alerts:
            st.info("Aún no hay hallazgos. Ejecuta la detección o revisa la partición seleccionada.")
        else:
            incident_by_alert = {alert_id: incident["incident_id"] for incident in incidents for alert_id in incident.get("alert_ids", [])}
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for index, alert in enumerate(sorted(alerts, key=lambda item: (order.get(item.get("severity"), 4), item.get("title", "")))[:6]):
                with st.container(key=f"soc-queue-row-{index}"):
                    info, action = st.columns([4, 1], vertical_alignment="center")
                    with info:
                        visual.alert_summary(alert)
                    incident_id = incident_by_alert.get(alert["alert_id"])
                    if incident_id:
                        action.button("Investigar →", key=f"investigate_{alert['alert_id']}", on_click=_focus_incident, args=(incident_id,))
            with st.expander("Todas las alertas y detalles de evidencia"):
                _alerts(alerts, incident_by_alert)
    with feed, st.container(key="soc-panel-feed"):
        visual.panel_heading("Últimos eventos del snapshot", "UTC")
        visual.activity_feed(events)
    if replay:
        st.caption(f"REPLAY hasta {as_of.isoformat()} · hallazgos transitorios de la última detección para este corte.")


def main() -> None:
    st.set_page_config(page_title="GSEC Sentinel · SOC", layout="wide", initial_sidebar_state="expanded")
    visual.apply_styles()
    with st.container(key="soc-shell"):
        _console()


def _console() -> None:
    api = SocApi(os.getenv("GSEC_API_BASE_URL", "http://127.0.0.1:8000"))
    header = st.empty()
    with st.sidebar, st.container(key="soc-sidebar"):
        visual.brand()
        st.html('<div class="soc-sidebar-label">WORKSPACE</div>')
        with st.container(key="soc-nav"):
            navigation = st.radio("Navegación", PAGES, key="nav", on_change=_nav_changed,
                                  format_func=lambda page: f"{PAGES.index(page) + 1:02d}  {page}", label_visibility="collapsed")
        st.html('<div class="soc-sidebar-label">CONTEXTO DE DATOS</div>')
        kind = st.selectbox("Tipo de dataset", ["synthetic", "official"], format_func=lambda value: "Sintético" if value == "synthetic" else "Oficial")
        dataset_id = st.text_input("ID del dataset").strip()
        replay = st.toggle("Reproducción histórica", key="replay_mode")
        if replay:
            chosen_date = st.date_input("Fecha de corte (UTC)", value=date.today(), key="replay_date")
            chosen_time = st.time_input("Hora de corte (UTC)", value=datetime.now(timezone.utc).time().replace(microsecond=0), key="replay_time")
            as_of = datetime.combine(chosen_date, chosen_time, tzinfo=timezone.utc)
        else:
            as_of = None
        st.html('<div class="soc-sidebar-label">OPERACIONES</div>')
        run_detection = st.button("Ejecutar detección hasta el corte" if replay else "Ejecutar detección", type="primary", width="stretch", disabled=not dataset_id)
        refresh = st.button("Actualizar datos", width="stretch")
    with header.container():
        visual.topbar(navigation, dataset_id, kind, as_of=as_of)
    if not dataset_id:
        st.html('<div class="soc-empty"><strong>Conecta una partición de telemetría</strong><br>Selecciona el tipo de dataset y escribe su identificador en el panel lateral. Después ejecuta la detección para abrir una investigación.</div>')
        return

    try:
        events = _fetch_events(api, kind, dataset_id, as_of, force=refresh or run_detection)
        if run_detection:
            with st.spinner("Ejecutando reglas de detección…"):
                result = api.run_detection(kind, dataset_id, as_of=as_of)
            if replay:
                if result.get("persisted") is not False:
                    raise ApiError("La API no confirmó que la detección histórica fuese transitoria.")
                st.session_state["replay_run"] = ((kind, dataset_id, as_of.isoformat()), result)
            else:
                if result.get("persisted") is not True:
                    raise ApiError("La API no confirmó la persistencia de la detección actual.")
                st.session_state.setdefault("current_runs", {})[(kind, dataset_id)] = result
            snapshot_key = (api.base_url, kind, dataset_id, as_of.isoformat() if as_of else None)
            st.session_state.setdefault("detection_snapshots", {})[snapshot_key] = (
                datetime.now(timezone.utc), frozenset(event["event_id"] for event in events),
            )
            st.success(f"Detección completada: {len(result.get('alert_ids', []))} alertas, {len(result.get('incident_ids', []))} incidentes.")
        if replay:
            run_key = (kind, dataset_id, as_of.isoformat())
            saved = st.session_state.get("replay_run")
            if saved and saved[0] == run_key:
                run_result = saved[1]
                if run_result.get("persisted") is not False:
                    raise ApiError("La API no confirmó que la detección histórica fuese transitoria.")
                alerts, incidents = detection_results_until(
                    run_result["alerts"], run_result["incidents"], events,
                    run_result.get("alert_ids", []), run_result.get("incident_ids", []),
                )
                findings_note = "Resultados transitorios calculados hasta el corte; no se guardaron como hallazgos actuales."
            else:
                alerts, incidents = [], []
                findings_note = "Ejecuta la detección para ver resultados asociados a este corte histórico."
        else:
            run_key = (kind, dataset_id)
            run_result = st.session_state.get("current_runs", {}).get(run_key)
            if run_result is None:
                alerts, incidents = [], []
                findings_note = "Ejecuta una detección completa para ver los hallazgos actuales de esta partición."
            else:
                alerts, incidents = detection_results_until(
                    api.alerts(kind, dataset_id), api.incidents(kind, dataset_id), events,
                    run_result.get("alert_ids", []), run_result.get("incident_ids", []),
                )
                findings_note = "Hallazgos de la última detección completa ejecutada en esta sesión para esta partición."
        _sync_incident(incidents, (kind, dataset_id, as_of.isoformat() if as_of else None))
    except (ApiError, KeyError, ValueError, TypeError) as exc:
        st.error("No se pudo conectar o completar la consulta de la API.")
        st.caption(str(exc))
        st.info("Comprueba la API, el puerto y el ID de dataset. Después pulsa Actualizar datos.")
        return

    loaded_at, fetched_live = st.session_state["event_cache_status"]
    with header.container():
        visual.topbar(navigation, dataset_id, kind, as_of=as_of, loaded_at=loaded_at, fetched=fetched_live)
    snapshot_key = (api.base_url, kind, dataset_id, as_of.isoformat() if as_of else None)
    detection_snapshot = st.session_state.get("detection_snapshots", {}).get(snapshot_key)
    if detection_snapshot and detection_snapshot[1] != frozenset(event["event_id"] for event in events):
        st.info("HALLAZGOS PENDIENTES DE ACTUALIZAR · los eventos de la API cambiaron desde la última detección. Ejecuta la detección para evaluar la telemetría consultada.")
    if navigation == "Investigation Workspace" and incidents and st.session_state.get("selected_incident") is None:
        st.session_state["selected_incident"] = incidents[0]["incident_id"]
    if navigation == "SOC Overview":
        has_detection = bool(saved and saved[0] == run_key) if replay else run_result is not None
        if not has_detection:
            st.caption("DETECCIÓN PENDIENTE · Los ceros de alertas e incidentes indican que todavía no hay resultados para esta vista.")
        _overview(events, alerts, incidents, replay, as_of)
    elif navigation == "Threat Hunting":
        with st.container(key="soc-panel-hunt"):
            _event_explorer(api, events, kind, dataset_id, replay)
    elif navigation == "Investigation Workspace":
        try:
            _investigation_workspace(api, events, alerts, incidents, kind, dataset_id, as_of)
        except (ApiError, KeyError, ValueError, TypeError) as exc:
            st.error(f"No se pudo abrir la investigación: {exc}")
    elif navigation == "Attack Replay":
        _attack_replay(events, alerts, incidents, as_of)
    else:
        with st.container(key="soc-panel-response"):
            _response_center(api, incidents, kind, dataset_id, replay)
    with st.expander("Contexto y estado de la consulta"):
        st.caption(f"Dataset {'SINTÉTICO: datos de prueba' if kind == 'synthetic' else 'OFICIAL'} · {dataset_id}")
        st.caption(findings_note)
        st.caption(f"API: {api.base_url} · eventos cargados: {loaded_at.isoformat()} · {'consulta HTTP' if fetched_live else 'memoria de sesión; TTL 60 s'}")
        selected = st.session_state.get("selected_incident")
        incident_title = next((item["title"] for item in incidents if item["incident_id"] == selected), "Sin incidente seleccionado")
        st.caption(f"Contexto del incidente: {incident_title}")
        if detection_snapshot:
            st.caption(f"Última detección ejecutada en esta sesión: {detection_snapshot[0].strftime('%Y-%m-%d %H:%M:%S UTC')}. Fecha de ejecución de la consola.")
        if replay:
            st.caption(f"Corte UTC: {as_of.isoformat()}. Respuesta y originales desactivados para proteger el límite temporal.")


if __name__ == "__main__":
    main()
