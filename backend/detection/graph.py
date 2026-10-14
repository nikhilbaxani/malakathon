"""Evidence-bound, deterministic attack graph for one incident partition."""

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
from typing import Sequence

import networkx as nx

from backend.models import Alert, Event, Incident


_CONNECTION_TYPES = {"network_connection", "data_transfer"}
_FILE_TYPES = {"file_write": "WROTE_FILE", "file_delete": "DELETED_FILE"}
_FILE_ATTEMPT_TYPES = {"file_write": "ATTEMPTED_WRITE_FILE", "file_delete": "ATTEMPTED_DELETE_FILE"}
_PROCESS_TYPES = {"process_start", *_FILE_TYPES}


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _node_id(partition: tuple[str, str], kind: str, value: str) -> str:
    payload = json.dumps((*partition, kind, value), ensure_ascii=False, separators=(",", ":"))
    return f"{kind}:{sha256(payload.encode('utf-8')).hexdigest()}"


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _destination_ip(event: Event) -> str | None:
    if event.event_type not in _CONNECTION_TYPES:
        return None
    candidate = _text(event.attributes.get("destination_ip"))
    if candidate is None:
        return None
    try:
        return str(ip_address(candidate))
    except ValueError:
        return None


def _unique_records(records: Sequence, id_name: str, partition: tuple[str, str]) -> dict:
    indexed = {}
    for record in records:
        if (record.dataset_kind, record.dataset_id) != partition:
            raise ValueError("records must belong to the incident partition")
        key = getattr(record, id_name)
        prior = indexed.get(key)
        if prior is not None and prior != record:
            raise ValueError(f"conflicting duplicate {id_name}: {key}")
        indexed[key] = record
    return indexed


def _provenance(event: Event) -> dict:
    details = {
        "event_id": event.event_id,
        "source": event.source,
        "raw_ref": event.raw_ref,
        "source_timestamp": event.source_timestamp,
    }
    if event.source_event_id is not None:
        details["source_event_id"] = event.source_event_id
    if event.source_record_number is not None:
        details["source_record_number"] = event.source_record_number
    return details


def build_attack_graph(
    incident: Incident,
    alerts: Sequence[Alert],
    events: Sequence[Event],
    *,
    as_of: datetime | None = None,
    max_nodes: int = 120,
) -> dict:
    """Return a JSON-ready DiGraph from validated references and explicit fields.

    Every edge is backed by one or more input events. An alert depending on a
    future event is wholly omitted at ``as_of``; only surviving alerts and their
    evidence contribute to the replay graph.
    """
    if max_nodes < 1:
        raise ValueError("max_nodes must be at least 1")
    if as_of is not None:
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError("as_of must include a timezone")
        as_of = as_of.astimezone(timezone.utc)

    partition = (incident.dataset_kind, incident.dataset_id)
    alert_by_id = _unique_records(alerts, "alert_id", partition)
    event_by_id = _unique_records(events, "event_id", partition)
    missing_alerts = set(incident.alert_ids) - alert_by_id.keys()
    missing_events = set(incident.evidence_event_ids) - event_by_id.keys()
    if missing_alerts or missing_events:
        raise ValueError(f"unresolved incident references: alerts={sorted(missing_alerts)}, events={sorted(missing_events)}")
    selected_alerts = [alert_by_id[alert_id] for alert_id in incident.alert_ids]
    for alert in selected_alerts:
        missing = set(alert.evidence_event_ids) - event_by_id.keys()
        if missing:
            raise ValueError(f"unresolved alert evidence: {sorted(missing)}")
        if not set(alert.evidence_event_ids).issubset(incident.evidence_event_ids):
            raise ValueError("alert evidence must be referenced by the incident")

    visible_alerts = [
        alert for alert in selected_alerts
        if as_of is None or all(event_by_id[eid].timestamp_utc <= as_of for eid in alert.evidence_event_ids)
    ]
    visible_event_ids = {
        eid for alert in visible_alerts for eid in alert.evidence_event_ids
    }
    visible_events = sorted(
        (event_by_id[eid] for eid in visible_event_ids),
        key=lambda event: (event.timestamp_utc, event.event_id),
    )

    graph = nx.DiGraph()

    def add_node(kind: str, value: str, attributes: dict | None = None) -> str:
        node_id = _node_id(partition, kind, value)
        graph.add_node(node_id, type=kind, label=value, attributes=attributes or {})
        return node_id

    def add_edge(source: str, target: str, relation: str, evidence: Sequence[Event], basis: str) -> None:
        if not evidence:
            raise ValueError("graph edges require evidence")
        prior = graph.get_edge_data(source, target)
        if prior is not None and (prior["type"] != relation or prior["basis"] != basis):
            raise ValueError("conflicting relation for DiGraph edge")
        all_evidence = {event.event_id: event for event in evidence}
        if prior is not None:
            all_evidence.update({eid: event_by_id[eid] for eid in prior["evidence_event_ids"]})
        ordered = sorted(all_evidence.values(), key=lambda event: (event.timestamp_utc, event.event_id))
        graph.add_edge(
            source,
            target,
            type=relation,
            evidence_event_ids=[event.event_id for event in ordered],
            time_start_utc=_utc(ordered[0].timestamp_utc),
            time_end_utc=_utc(ordered[-1].timestamp_utc),
            provenance=[_provenance(event) for event in ordered],
            basis=basis,
        )

    if visible_alerts:
        incident_node = add_node("incident", incident.incident_id, {"status": incident.status})
    else:
        incident_node = None

    for event in visible_events:
        event_node = add_node(
            "event", event.event_id,
            {"event_type": event.event_type, "timestamp_utc": _utc(event.timestamp_utc)},
        )
        user = _text(event.attributes.get("user"))
        host = _text(event.attributes.get("host"))
        if user:
            user_node = add_node("user", user)
            add_edge(event_node, user_node, "HAS_USER", [event], "observed")
        if host:
            host_node = add_node("host", host)
            add_edge(event_node, host_node, "HAS_HOST", [event], "observed")
        if user and host:
            add_edge(user_node, host_node, "OBSERVED_ON", [event], "observed")

        destination = _destination_ip(event)
        if destination:
            ip_node = add_node("ip", destination)
            add_edge(event_node, ip_node, "DESTINATION_IP", [event], "observed")
            if host and event.attributes.get("outcome") == "success":
                add_edge(host_node, ip_node, "CONNECTED_TO", [event], "observed")

        if event.event_type in _PROCESS_TYPES:
            process = _text(event.attributes.get("process"))
            if process:
                process_node = add_node("process", process)
                add_edge(event_node, process_node, "HAS_PROCESS", [event], "observed")
        if event.event_type in _FILE_TYPES:
            file_path = _text(event.attributes.get("file_path"))
            if file_path:
                file_node = add_node("file", file_path)
                outcome = event.attributes.get("outcome")
                if outcome == "success":
                    relation = _FILE_TYPES[event.event_type]
                elif isinstance(outcome, str) and outcome in {"denied", "failure"}:
                    relation = _FILE_ATTEMPT_TYPES[event.event_type]
                else:
                    relation = "TARGET_FILE"
                add_edge(event_node, file_node, relation, [event], "observed")

    for alert in sorted(visible_alerts, key=lambda item: item.alert_id):
        alert_node = add_node("alert", alert.alert_id, {"rule_id": alert.rule_id, "severity": alert.severity})
        evidence = [event_by_id[eid] for eid in alert.evidence_event_ids]
        for event in evidence:
            add_edge(_node_id(partition, "event", event.event_id), alert_node, "EVIDENCE_FOR", [event], "derived")
        add_edge(alert_node, incident_node, "PART_OF", evidence, "derived")

    # Keep incident, then alerts, evidence events, and observed entities.
    priority = {"incident": 0, "alert": 1, "event": 2, "user": 3, "host": 4, "ip": 5, "process": 6, "file": 7}
    ordered_nodes = sorted(graph.nodes, key=lambda node: (priority[graph.nodes[node]["type"]], node))
    selected = set(ordered_nodes[:max_nodes])
    result_nodes = [{"id": node, **graph.nodes[node]} for node in ordered_nodes if node in selected]
    result_edges = [
        {"source": source, "target": target, **data}
        for source, target, data in graph.edges(data=True)
        if source in selected and target in selected
    ]
    result_edges.sort(key=lambda edge: (edge["source"], edge["target"], edge["type"]))
    truncated = len(selected) < graph.number_of_nodes()
    return {
        "nodes": result_nodes,
        "edges": result_edges,
        "metadata": {
            "dataset_kind": partition[0],
            "dataset_id": partition[1],
            "incident_id": incident.incident_id,
            "as_of": _utc(as_of) if as_of is not None else None,
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
            "node_count": len(result_nodes),
            "edge_count": len(result_edges),
            "returned_nodes": len(result_nodes),
            "returned_edges": len(result_edges),
            "truncated": truncated,
            "omitted_nodes": graph.number_of_nodes() - len(selected),
            "limitations": [
                "Only explicit event fields and validated alert references create relationships.",
                "Co-occurrence of user and host does not prove authentication or control.",
                "Completed connection and file-action edges require explicit outcome=success.",
                *(["Graph was truncated to max_nodes; omitted edges are not returned."] if truncated else []),
            ],
        },
    }
