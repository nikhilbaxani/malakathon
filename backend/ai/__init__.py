"""Evidence-bound triage with an offline default and an opt-in Jev adapter.

The Jev call uses TypeSafe's official Python SDK. Only aggregate counts from
explicitly synthetic datasets leave the process; event contents, IDs, titles,
timestamps, attributes and raw telemetry are never passed to the provider.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from backend.models import Alert, Event, Incident, TriageResult


def _validate_inputs(
    incident: Incident,
    alerts: Sequence[Alert],
    evidence: Sequence[Event],
    generated_at: datetime,
) -> datetime:
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must include a timezone")
    if len(alerts) != len(incident.alert_ids) or {a.alert_id for a in alerts} != set(incident.alert_ids):
        raise ValueError("alerts must resolve every incident alert ID exactly once")
    if len(evidence) != len(incident.evidence_event_ids) or {e.event_id for e in evidence} != set(
        incident.evidence_event_ids
    ):
        raise ValueError("evidence must resolve every incident event ID exactly once")
    partition = (incident.dataset_kind, incident.dataset_id)
    if any((a.dataset_kind, a.dataset_id) != partition for a in alerts):
        raise ValueError("alert belongs to another dataset partition")
    if any((e.dataset_kind, e.dataset_id) != partition for e in evidence):
        raise ValueError("event belongs to another dataset partition")
    if any(not set(a.evidence_event_ids).issubset(incident.evidence_event_ids) for a in alerts):
        raise ValueError("alert evidence is absent from incident evidence")
    return generated_at.astimezone(timezone.utc)


def _result(
    incident: Incident,
    *,
    engine: str,
    summary: str,
    rationale: str,
    generated_at: datetime,
) -> TriageResult:
    identity = f"{incident.dataset_kind}/{incident.dataset_id}/{incident.incident_id}/{generated_at.isoformat()}/{engine}"
    return TriageResult(
        triage_id=f"triage-{uuid5(NAMESPACE_URL, identity)}",
        incident_id=incident.incident_id,
        engine=engine,
        assessment="needs_review",
        summary=summary,
        rationale=rationale,
        generated_at=generated_at,
        evidence_event_ids=list(incident.evidence_event_ids),
    )


class DeterministicTriageEngine:
    """Conservative, reproducible triage without a network dependency."""

    def triage(
        self,
        incident: Incident,
        *,
        alerts: Sequence[Alert],
        evidence: Sequence[Event],
        generated_at: datetime,
    ) -> TriageResult:
        at = _validate_inputs(incident, alerts, evidence, generated_at)
        severities = Counter(alert.severity for alert in alerts)
        highest = next(level for level in ("critical", "high", "medium", "low") if severities[level])
        summary = (
            f"Revisión humana pendiente: {len(alerts)} alerta(s), "
            f"{len(evidence)} evento(s) y severidad máxima {highest}."
        )
        rationale = (
            "Las reglas aportan indicios vinculados a los ID de evidencia; "
            "no prueban por sí solas intrusión, exfiltración ni sabotaje. "
            "Verificar los eventos originales antes de decidir."
        )
        return _result(
            incident, engine="deterministic", summary=summary, rationale=rationale, generated_at=at
        )


def _official_client(api_key: str, timeout: float) -> Any:
    # Optional import: the SOC remains functional without this SDK installed.
    from typesafe_sdk import RetryPolicy, TypeSafeClient

    return TypeSafeClient(
        api_key=api_key,
        base_url="https://api.typesafe.ai",
        model="jev-latest",
        timeout=timeout,
        retry=RetryPolicy(max_retries=0),
    )


class JevTriageEngine:
    """Optional review-priority suggestion, with deterministic failure fallback."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout: float = 3.0,
        client_factory: Callable[[str, float], Any] | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("api_key must be supplied explicitly")
        if not 0 < timeout <= 30:
            raise ValueError("timeout must be between 0 and 30 seconds")
        self._api_key = api_key
        self._timeout = timeout
        self._client_factory = client_factory or _official_client
        self._fallback = DeterministicTriageEngine()

    def triage(
        self,
        incident: Incident,
        *,
        alerts: Sequence[Alert],
        evidence: Sequence[Event],
        generated_at: datetime,
    ) -> TriageResult:
        at = _validate_inputs(incident, alerts, evidence, generated_at)
        if incident.dataset_kind != "synthetic":
            return self._fallback.triage(
                incident, alerts=alerts, evidence=evidence, generated_at=at
            )

        severity_counts = Counter(alert.severity for alert in alerts)
        # A strict allowlist prevents free-form telemetry or rule names leaking.
        state = {
            "alert_count": len(alerts),
            "severity_counts": {
                level: severity_counts[level] for level in ("low", "medium", "high", "critical")
            },
        }
        questions = {
            "review_priority": {
                "type": "choice",
                "instructions": "Based only on these synthetic alert counts, choose human review priority. This is not a finding about whether an attack occurred.",
                "criteria": {
                    "urgent_review": "A human should inspect this promptly.",
                    "standard_review": "A human should inspect this in the normal queue.",
                },
            }
        }
        try:
            with self._client_factory(self._api_key, self._timeout) as client:
                response = client.system_one(state=state, questions=questions, timeout=self._timeout)
            choice = response.choices["review_priority"].choice
            if choice not in {"urgent_review", "standard_review"}:
                raise ValueError("unexpected Jev choice")
        except Exception:
            # Includes missing optional SDK, transport errors, timeouts and bad responses.
            return self._fallback.triage(
                incident, alerts=alerts, evidence=evidence, generated_at=at
            )

        priority = "urgente" if choice == "urgent_review" else "ordinaria"
        return _result(
            incident,
            engine="jev",
            summary=f"Jev sugiere revisión humana {priority} de las alertas sintéticas.",
            rationale=(
                "Sugerencia de prioridad basada solo en conteos de alertas por severidad; "
                "es una evaluación del modelo, no un hecho de telemetría ni una confirmación de ataque."
            ),
            generated_at=at,
        )


def create_triage_engine(
    *,
    enable_jev: bool = False,
    api_key: str | None = None,
    timeout: float = 3.0,
    client_factory: Callable[[str, float], Any] | None = None,
) -> DeterministicTriageEngine | JevTriageEngine:
    """Use Jev only after explicit opt-in with a key; otherwise stay offline."""
    if enable_jev and api_key and api_key.strip():
        return JevTriageEngine(api_key=api_key, timeout=timeout, client_factory=client_factory)
    return DeterministicTriageEngine()


__all__ = ["DeterministicTriageEngine", "JevTriageEngine", "create_triage_engine"]
