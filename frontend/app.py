"""GSEC Sentinel SOC console. Start with: streamlit run frontend/app.py"""

from __future__ import annotations

import os
from datetime import date, datetime, timezone
from typing import Any

import streamlit as st
import streamlit.components.v1 as components

from frontend.api import ApiError, SocApi
from frontend.graph import MAX_NODES, graph_view, missing_optional_types, render_graph_html
from frontend.replay import detection_results_until, events_until, parse_utc, timeline


def _table(items: list[dict[str, Any]], columns: list[str], labels: list[str]) -> None:
    st.dataframe(
        [{label: item.get(column, "") for column, label in zip(columns, labels)} for item in items],
        use_container_width=True,
        hide_index=True,
    )


def _event_explorer(events: list[dict[str, Any]]) -> None:
    st.subheader("Explorador de eventos")
    types = sorted({str(event.get("event_type", "")) for event in events})
    selected_type = st.selectbox("Tipo de evento", ["Todos", *types])
    search = st.text_input("Buscar por ID, origen o atributos")
    shown = [
        event for event in events
        if (selected_type == "Todos" or event.get("event_type") == selected_type)
        and (not search or search.casefold() in str(event).casefold())
    ]
    st.caption(f"{len(shown)} eventos visibles")
    _table(
        shown,
        ["timestamp_utc", "event_id", "source_event_id", "event_type", "source", "raw_ref"],
        ["UTC", "ID", "ID de origen", "Tipo", "Origen", "Referencia original"],
    )
    if shown:
        event_id = st.selectbox("Inspeccionar evento", [event["event_id"] for event in shown])
        st.json(next(event for event in shown if event["event_id"] == event_id))


def _alerts(alerts: list[dict[str, Any]]) -> None:
    st.subheader("Alertas")
    st.caption("Cada alerta muestra los IDs de eventos que sustentan la detección.")
    _table(
        alerts,
        ["severity", "detected_at", "title", "rule_id", "alert_id", "evidence_event_ids"],
        ["Severidad", "Detectada en UTC", "Título", "Regla", "ID", "Evidencia (IDs)"],
    )
    for alert in alerts:
        with st.expander(f"{alert['severity'].upper()} · {alert['title']} · {alert['alert_id']}"):
            st.write(alert.get("description", ""))
            st.write("Eventos de evidencia:", alert.get("evidence_event_ids", []))


def _incident_detail(api: SocApi, incident_id: str, kind: str, dataset_id: str) -> None:
    detail = api.incident_detail(incident_id, kind, dataset_id)
    incident = detail["incident"]
    st.json(incident)
    st.markdown("**Evidencia y cronología**")
    st.dataframe(timeline(detail.get("events", [])), use_container_width=True, hide_index=True)
    st.markdown("**Evaluaciones de triage**")
    for result in detail.get("triage_results", []):
        st.write(f"{result['engine']} · {result['assessment']} · {result['generated_at']}")
        st.write(result["summary"])
        st.caption(result["rationale"])
    st.markdown("**Acciones registradas**")
    for action in detail.get("containment_actions", []):
        label = "SIMULACIÓN" if action.get("mode") == "simulation" else "ACCIÓN REAL"
        st.write(f"{label} · {action['action_type']} · {action['target']} · {action['status']}")

    if st.button("Evaluar triage", key=f"triage_{incident_id}"):
        result = api.triage(incident_id, kind, dataset_id)
        st.success(f"Triage {result['triage_id']} registrado con motor {result['engine']}.")
        st.json(result)
    with st.form(f"simulation_{incident_id}"):
        st.markdown("**Registrar simulación de contención**")
        action_type = st.text_input("Tipo de acción", placeholder="Ej.: aislar_host")
        target = st.text_input("Objetivo", placeholder="Identificador del recurso")
        evidence = st.multiselect(
            "IDs de eventos de evidencia",
            incident.get("evidence_event_ids", []),
            default=incident.get("evidence_event_ids", []),
        )
        submitted = st.form_submit_button("Simular acción")
    if submitted:
        if not action_type.strip() or not target.strip() or not evidence:
            st.error("Indica tipo, objetivo y al menos un evento de evidencia.")
        else:
            result = api.simulate(incident_id, kind, dataset_id, action_type.strip(), target.strip(), evidence)
            if result.get("mode") != "simulation":
                st.error("La API devolvió una acción que no está etiquetada como simulación.")
            else:
                st.success(f"SIMULACIÓN registrada: {result['action_id']} ({result['status']}).")


def _incidents(api: SocApi, incidents: list[dict[str, Any]], kind: str, dataset_id: str, replay: bool) -> None:
    st.subheader("Incidentes")
    _table(
        incidents,
        ["status", "created_at", "title", "incident_id", "alert_ids", "evidence_event_ids"],
        ["Estado", "Creado en UTC", "Título", "ID", "Alertas (IDs)", "Evidencia (IDs)"],
    )
    if not incidents:
        return
    if replay:
        st.info("El detalle y las acciones están desactivados en replay: esta API no ofrece un detalle con corte histórico.")
        return
    incident_id = st.selectbox("Abrir incidente", [incident["incident_id"] for incident in incidents])
    _incident_detail(api, incident_id, kind, dataset_id)


def _attack_graph(
    api: SocApi, incidents: list[dict[str, Any]], events: list[dict[str, Any]],
    kind: str, dataset_id: str, as_of: datetime | None,
) -> None:
    st.subheader("Attack Graph")
    if kind == "synthetic":
        st.warning("GRAFO SINTÉTICO: relaciones derivadas de datos de prueba.")
    if not incidents:
        st.info("Ejecuta una detección para seleccionar un incidente y consultar su grafo.")
        return
    incident_id = st.selectbox("Incidente del grafo", [item["incident_id"] for item in incidents])
    try:
        graph = api.incident_graph(incident_id, kind, dataset_id, as_of=as_of, max_nodes=MAX_NODES)
        metadata = graph.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Metadatos de grafo inválidos")
        if metadata.get("dataset_kind") != kind or metadata.get("dataset_id") != dataset_id:
            raise ValueError("El grafo recibido no corresponde a la partición seleccionada")
        if as_of is not None:
            if not metadata.get("as_of") or parse_utc(metadata["as_of"]) != as_of:
                raise ValueError("El grafo histórico recibido no confirma el corte temporal")
        node_types = sorted({str(node.get("type", "OTRO")) for node in graph.get("nodes", []) if isinstance(node, dict)})
        chosen_types = st.multiselect("Filtrar tipos de nodos", node_types, default=node_types)
        layout = st.selectbox("Disposición", ["Capas", "Circular"])
        visible_ids = {event["event_id"] for event in events} if as_of is not None else None
        nodes, edges, ui_truncated = graph_view(
            graph, selected_types=set(chosen_types), visible_event_ids=visible_ids, as_of=as_of,
        )
    except (ApiError, ValueError, KeyError, TypeError) as exc:
        st.error(f"No se pudo consultar el grafo: {exc}")
        return
    st.caption(f"{len(nodes)} nodos y {len(edges)} relaciones visibles · máximo {MAX_NODES} nodos")
    if metadata.get("truncated") or ui_truncated:
        st.warning("Grafo parcial: se alcanzó el límite de nodos o relaciones. Ajusta el filtro para explorar una parte.")
    for limitation in metadata.get("limitations", []):
        st.info(f"Limitación del grafo: {limitation}")
    absent = missing_optional_types(node_types)
    if absent:
        st.caption("Entidades opcionales no presentes: " + ", ".join(absent) + ". El grafo puede ser parcial.")
    if not nodes:
        st.info("No hay nodos para el filtro seleccionado.")
        return
    components.html(render_graph_html(nodes, edges, layout=layout), height=750, scrolling=False)
    st.markdown("**Inspección de evidencia**")
    event_by_id = {event["event_id"]: event for event in events}
    node_by_id = {node["id"]: node for node in nodes}
    node_id = st.selectbox("Nodo", list(node_by_id), format_func=lambda value: str(node_by_id[value].get("label", value)))
    st.json(node_by_id[node_id])
    if edges:
        edge_index = st.selectbox(
            "Relación", list(range(len(edges))),
            format_func=lambda index: f"{edges[index]['source']} → {edges[index]['target']} · {edges[index].get('type', '')}",
        )
        edge = edges[edge_index]
        st.json(edge)
        evidence_ids = edge.get("evidence_event_ids", [])
        st.write("IDs de eventos de evidencia:", evidence_ids)
        available = [event_id for event_id in evidence_ids if event_id in event_by_id]
        if available:
            evidence_id = st.selectbox("Ver evento de evidencia", available)
            st.json(event_by_id[evidence_id])
        elif evidence_ids:
            st.caption("Los eventos referenciados no están en la página visible de esta consulta.")


def main() -> None:
    st.set_page_config(page_title="GSEC Sentinel", page_icon="🛡️", layout="wide")
    st.title("GSEC Sentinel")
    st.caption("Consola SOC · UTC · datos y conclusiones ligados a evidencia")

    api = SocApi(os.getenv("GSEC_API_BASE_URL", "http://127.0.0.1:8000"))
    with st.sidebar:
        st.header("Consulta")
        kind = st.selectbox("Tipo de dataset", ["synthetic", "official"], format_func=lambda value: "Sintético" if value == "synthetic" else "Oficial")
        dataset_id = st.text_input("ID del dataset").strip()
        replay = st.toggle("Reproducción histórica")
        if replay:
            chosen_date = st.date_input("Fecha de corte (UTC)", value=date.today())
            chosen_time = st.time_input("Hora de corte (UTC)", value=datetime.now(timezone.utc).time().replace(microsecond=0))
            as_of = datetime.combine(chosen_date, chosen_time, tzinfo=timezone.utc)
            st.caption(f"Solo eventos con timestamp_utc ≤ {as_of.isoformat()}.")
        else:
            as_of = None
        st.caption(f"API: {api.base_url}")

    if kind == "synthetic":
        st.warning("DATASET SINTÉTICO: los registros y hallazgos de esta partición son datos de prueba.")
    else:
        st.info("DATASET OFICIAL: la consola muestra únicamente lo recibido de la API para la partición seleccionada.")
    if not dataset_id:
        st.info("Introduce el ID del dataset para consultar la API.")
        return

    try:
        events = api.all_events(kind, dataset_id, as_of=as_of)
        if replay:
            events = events_until(events, as_of)
            run_key = (kind, dataset_id, as_of.isoformat())
            if st.button("Ejecutar detección hasta el corte"):
                st.session_state["replay_run"] = (run_key, api.run_detection(kind, dataset_id, as_of=as_of))
            saved = st.session_state.get("replay_run")
            if saved and saved[0] == run_key:
                run_result = saved[1]
                if run_result.get("persisted") is not False:
                    raise ApiError("La API no confirmó que la detección histórica fuese transitoria.")
                alerts, incidents = detection_results_until(
                    run_result["alerts"], run_result["incidents"], events,
                    run_result.get("alert_ids", []), run_result.get("incident_ids", []),
                )
                st.caption("Resultados transitorios calculados hasta el corte; no se guardaron como hallazgos actuales.")
            else:
                alerts, incidents = [], []
                st.caption("Ejecuta la detección para ver resultados asociados a este corte histórico.")
        else:
            run_key = (kind, dataset_id)
            if st.button("Ejecutar detección"):
                result = api.run_detection(kind, dataset_id)
                st.session_state.setdefault("current_runs", {})[run_key] = result
                st.success(f"Detección registrada: {len(result.get('alert_ids', []))} alertas, {len(result.get('incident_ids', []))} incidentes.")
            run_result = st.session_state.get("current_runs", {}).get(run_key)
            if run_result is None:
                alerts, incidents = [], []
                st.caption("Ejecuta una detección completa para ver los hallazgos actuales de esta partición.")
            else:
                alerts, incidents = detection_results_until(
                    api.alerts(kind, dataset_id), api.incidents(kind, dataset_id), events,
                    run_result.get("alert_ids", []), run_result.get("incident_ids", []),
                )
                st.caption("Hallazgos de la última detección completa ejecutada en esta sesión para esta partición.")
    except (ApiError, KeyError, ValueError, TypeError) as exc:
        st.error(f"No se pudo completar la consulta: {exc}")
        return

    dashboard, explorer, alert_tab, incident_tab, history, graph_tab = st.tabs(
        ["Dashboard", "Eventos", "Alertas", "Incidentes", "Línea temporal", "Attack Graph"]
    )
    with dashboard:
        if replay:
            st.info(f"REPLAY hasta {as_of.isoformat()} · resultados de detección solo si se ejecutó para este corte.")
        left, middle, right = st.columns(3)
        left.metric("Eventos visibles", len(events))
        middle.metric("Alertas visibles", len(alerts))
        right.metric("Incidentes visibles", len(incidents))
        if incidents:
            st.markdown("**Incidentes por estado**")
            counts = {status: sum(incident.get("status") == status for incident in incidents) for status in ("open", "investigating", "contained", "closed")}
            st.bar_chart([{"Estado": status, "Incidentes": count} for status, count in counts.items()], x="Estado", y="Incidentes")
    with explorer:
        _event_explorer(events)
    with alert_tab:
        _alerts(alerts)
    with incident_tab:
        try:
            _incidents(api, incidents, kind, dataset_id, replay)
        except (ApiError, KeyError, ValueError, TypeError) as exc:
            st.error(f"No se pudo abrir el incidente: {exc}")
    with history:
        st.subheader("Línea temporal de eventos")
        st.dataframe(timeline(events), use_container_width=True, hide_index=True)
    with graph_tab:
        _attack_graph(api, incidents, events, kind, dataset_id, as_of)


if __name__ == "__main__":
    main()
