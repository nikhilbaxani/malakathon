"""Conservative, documented signals; no inference from unrecognized telemetry."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from typing import Sequence
from uuid import NAMESPACE_URL, uuid5

from backend.models import Alert, DetectionResult, Event, Incident


EXFIL_WINDOW = timedelta(minutes=10)
EXFIL_MIN_BYTES = 10 * 1024 * 1024
INCIDENT_WINDOW = timedelta(hours=1)

PRIVILEGE_RULE = "privilege_escalation_v1"
EXFIL_RULE = "possible_exfiltration_v1"
SABOTAGE_RULE = "possible_sabotage_v1"


def _entity(event: Event) -> tuple[str, str] | None:
    """Only explicit, nonempty user and host fields permit correlation."""
    user = event.attributes.get("user")
    host = event.attributes.get("host")
    if isinstance(user, str) and user.strip() and isinstance(host, str) and host.strip():
        return user, host
    return None


def _stable_id(prefix: str, *parts: str) -> str:
    return f"{prefix}-{uuid5(NAMESPACE_URL, json.dumps(parts, ensure_ascii=False))}"


def _alert(
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    evidence: Sequence[Event],
    detected_at: datetime,
) -> Alert:
    first = evidence[0]
    ids = sorted({event.event_id for event in evidence})
    return Alert(
        alert_id=_stable_id("alert", first.dataset_kind, first.dataset_id, rule_id, *ids),
        dataset_kind=first.dataset_kind,
        dataset_id=first.dataset_id,
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        detected_at=detected_at,
        evidence_event_ids=ids,
    )


def _is_success(event: Event) -> bool:
    return event.attributes.get("outcome") == "success"


def _is_privilege_escalation(event: Event) -> bool:
    if event.event_type != "privilege_change" or not _is_success(event):
        return False
    before = event.attributes.get("old_role")
    after = event.attributes.get("new_role")
    return (
        isinstance(before, str)
        and isinstance(after, str)
        and bool(before.strip())
        and before.strip().lower() not in {"admin", "administrator", "root"}
        and after.strip().lower() in {"admin", "administrator", "root"}
    )


def _outbound_external_bytes(event: Event) -> int | None:
    if event.event_type != "data_transfer":
        return None
    attrs = event.attributes
    if attrs.get("direction") != "outbound" or attrs.get("destination_scope") != "external":
        return None
    count = attrs.get("bytes")
    if type(count) is int:
        return count if count > 0 else None
    if isinstance(count, str) and count and count.isascii() and count.isdecimal():
        try:
            parsed = int(count)
        except ValueError:  # Includes Python's maximum integer-string length guard.
            return None
        return parsed if parsed > 0 else None
    return None


def _is_sabotage(event: Event) -> bool:
    return event.event_type in {
        "backup_deleted",
        "audit_logging_disabled",
        "service_stopped",
    } and _is_success(event)


class RuleBasedDetectionEngine:
    """Run local rules on a prefiltered, single-partition sequence of events.

    The caller is responsible for the time interval and replay ``as_of`` cut.
    Neither alert nor incident creation uses an event outside ``events``.
    """

    def detect(self, events: Sequence[Event], *, detected_at: datetime) -> DetectionResult:
        if detected_at.tzinfo is None or detected_at.utcoffset() is None:
            raise ValueError("detected_at must include a timezone")
        detected_at = detected_at.astimezone(timezone.utc)
        if not events:
            return DetectionResult()

        partition = (events[0].dataset_kind, events[0].dataset_id)
        event_by_id: dict[str, Event] = {}
        for event in events:
            if (event.dataset_kind, event.dataset_id) != partition:
                raise ValueError("events must belong to one dataset partition")
            previous = event_by_id.get(event.event_id)
            if previous is not None and previous != event:
                raise ValueError("duplicate event_id has conflicting records")
            event_by_id[event.event_id] = event

        ordered = sorted(event_by_id.values(), key=lambda event: (event.timestamp_utc, event.event_id))
        alerts: list[Alert] = []
        transfers: dict[tuple[str, str], list[tuple[Event, int]]] = defaultdict(list)
        alert_entities: dict[str, tuple[str, str]] = {}
        alert_times: dict[str, datetime] = {}

        def record(alert: Alert, entity: tuple[str, str], time: datetime) -> None:
            alerts.append(alert)
            alert_entities[alert.alert_id] = entity
            alert_times[alert.alert_id] = time

        for event in ordered:
            entity = _entity(event)
            if entity is None:
                continue
            if _is_privilege_escalation(event):
                record(
                    _alert(
                        PRIVILEGE_RULE,
                        "Escalada de privilegios observada",
                        "Hecho: el registro indica un cambio exitoso desde un rol no administrador a administrador. "
                        "Hipótesis: el cambio podría ser parte de una intrusión; requiere validar autorización.",
                        "high",
                        [event],
                        detected_at,
                    ),
                    entity,
                    event.timestamp_utc,
                )
            if _is_sabotage(event):
                record(
                    _alert(
                        SABOTAGE_RULE,
                        "Posible sabotaje",
                        f"Hecho: se registró {event.event_type} con resultado success. "
                        "Hipótesis: podría tratarse de sabotaje; requiere verificar contexto y autorización.",
                        "high",
                        [event],
                        detected_at,
                    ),
                    entity,
                    event.timestamp_utc,
                )
            byte_count = _outbound_external_bytes(event)
            if byte_count is not None:
                transfers[entity].append((event, byte_count))

        for entity, entries in transfers.items():
            # Greedy, non-overlapping batches: each evidence event contributes once.
            batch: list[tuple[Event, int]] = []
            for event, count in entries:
                batch = [(item, size) for item, size in batch if event.timestamp_utc - item.timestamp_utc <= EXFIL_WINDOW]
                batch.append((event, count))
                total = sum(size for _, size in batch)
                if total < EXFIL_MIN_BYTES:
                    continue
                evidence = [item for item, _ in batch]
                record(
                    _alert(
                        EXFIL_RULE,
                        "Posible exfiltración",
                        f"Hecho: {total} bytes salientes hacia destinos marcados externos en hasta 10 minutos. "
                        "Hipótesis: la transferencia podría ser exfiltración; requiere revisar destino y autorización.",
                        "high",
                        evidence,
                        detected_at,
                    ),
                    entity,
                    event.timestamp_utc,
                )
                batch = []

        alerts.sort(key=lambda alert: (alert_times[alert.alert_id], alert.rule_id, alert.alert_id))
        alerts_by_entity: dict[tuple[str, str], list[Alert]] = defaultdict(list)
        for alert in alerts:
            alerts_by_entity[alert_entities[alert.alert_id]].append(alert)

        incidents: list[Incident] = []
        for entity, entity_alerts in alerts_by_entity.items():
            group: list[Alert] = []
            last_time: datetime | None = None
            for alert in entity_alerts:
                time = alert_times[alert.alert_id]
                if group and last_time is not None and time - last_time > INCIDENT_WINDOW:
                    incidents.append(self._incident(group, partition, entity, detected_at))
                    group = []
                group.append(alert)
                last_time = time
            if group:
                incidents.append(self._incident(group, partition, entity, detected_at))
        incidents.sort(key=lambda incident: incident.incident_id)
        return DetectionResult(alerts=alerts, incidents=incidents)

    @staticmethod
    def _incident(
        alerts: Sequence[Alert],
        partition: tuple[str, str],
        entity: tuple[str, str],
        detected_at: datetime,
    ) -> Incident:
        alert_ids = sorted(alert.alert_id for alert in alerts)
        evidence_ids = sorted({event_id for alert in alerts for event_id in alert.evidence_event_ids})
        return Incident(
            incident_id=_stable_id("incident", partition[0], partition[1], *alert_ids),
            dataset_kind=partition[0],
            dataset_id=partition[1],
            title=f"Actividad de seguridad: {entity[0]} en {entity[1]}",
            status="open",
            created_at=detected_at,
            alert_ids=alert_ids,
            evidence_event_ids=evidence_ids,
        )
