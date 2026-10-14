"""Pure selection rules used by the console's historical view."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp sin zona horaria")
    return parsed.astimezone(timezone.utc)


def events_until(events: list[dict[str, Any]], as_of: datetime) -> list[dict[str, Any]]:
    """Enforce the cutoff even if a server accidentally returns later events."""
    cutoff = as_of.astimezone(timezone.utc)
    return [event for event in events if parse_utc(event["timestamp_utc"]) <= cutoff]


def detection_results_until(
    alerts: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    visible_events: list[dict[str, Any]],
    alert_ids: list[str],
    incident_ids: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Show only results from this replay run backed by visible evidence."""
    event_ids = {event["event_id"] for event in visible_events}
    run_alert_ids = set(alert_ids)
    run_incident_ids = set(incident_ids)
    selected_alerts = [
        alert for alert in alerts
        if alert["alert_id"] in run_alert_ids
        and alert.get("evidence_event_ids")
        and set(alert["evidence_event_ids"]) <= event_ids
    ]
    visible_alert_ids = {alert["alert_id"] for alert in selected_alerts}
    selected_incidents = [
        incident for incident in incidents
        if incident["incident_id"] in run_incident_ids
        and incident.get("evidence_event_ids")
        and set(incident["evidence_event_ids"]) <= event_ids
        and set(incident.get("alert_ids", [])) <= visible_alert_ids
    ]
    return selected_alerts, selected_incidents


def timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a chronological view from source events alone."""
    return [
        {
            "UTC": event["timestamp_utc"],
            "ID": event["event_id"],
            "Tipo": event["event_type"],
            "Origen": event["source"],
            "ID de origen": event.get("source_event_id") or "",
        }
        for event in sorted(events, key=lambda item: (parse_utc(item["timestamp_utc"]), item["event_id"]))
    ]
