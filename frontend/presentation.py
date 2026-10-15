"""Small, deterministic presentation helpers; never infer telemetry or compromise."""
from __future__ import annotations

from typing import Any

from frontend.replay import parse_utc

SEVERITIES = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA", "info": "INFORMATIVA"}
ENTITY_FIELDS = {
    "Usuario": ("user", "username", "user_name"),
    "Host": ("host", "hostname", "host_name"),
    "IP": ("source_ip", "destination_ip", "src_ip", "dst_ip", "ip"),
    "Archivo": ("file_path", "filename", "file_name"),
    "Proceso": ("process", "process_name"),
}


def severity_label(value: str) -> str:
    return SEVERITIES.get(value, value.upper())


def event_label(event: dict[str, Any], index: int | None = None) -> str:
    stamp = parse_utc(event["timestamp_utc"]).strftime("%d %b %H:%M:%S UTC")
    attrs = event.get("attributes", {})
    subject = attrs.get("host") or attrs.get("user") or event.get("source", "")
    prefix = f"E{index + 1:03d} · " if index is not None else ""
    return f"{prefix}{stamp} · {event['event_type']} · {subject}"


def event_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda item: (parse_utc(item["timestamp_utc"]), item["event_id"]))
    return [
        {"Evento": f"E{index + 1:03d}", "UTC": parse_utc(event["timestamp_utc"]).strftime("%Y-%m-%d %H:%M:%S"),
         "Tipo": event["event_type"], "Origen": event.get("source", ""),
         "Usuario": event.get("attributes", {}).get("user", ""),
         "Host": event.get("attributes", {}).get("host", "")}
        for index, event in enumerate(ordered)
    ]


def entity_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observed: dict[tuple[str, str], set[str]] = {}
    for event in events:
        attrs = event.get("attributes", {})
        for kind, fields in ENTITY_FIELDS.items():
            for field in fields:
                value = attrs.get(field)
                if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
                    observed.setdefault((kind, str(value)), set()).add(event["event_id"])
    return [{"Tipo": kind, "Entidad observada": value, "Eventos": len(ids)}
            for (kind, value), ids in sorted(observed.items())]


def relation_label(index: int, edge: dict[str, Any], node_by_id: dict[str, dict[str, Any]]) -> str:
    source = node_by_id.get(edge["source"], {}).get("label", "Origen")
    target = node_by_id.get(edge["target"], {}).get("label", "Destino")
    basis = "DERIVADA" if edge.get("basis") == "derived" else "OBSERVADA"
    return f"R{index + 1:03d} · {source} → {target} · {edge.get('type', '')} · {basis}"
