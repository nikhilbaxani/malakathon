"""Storage interfaces; implementations belong to the data module."""

from datetime import datetime
from typing import Literal, Mapping, Protocol, Sequence

from backend.models import (
    Alert,
    ContainmentAction,
    DatasetKind,
    DetectionResult,
    Event,
    Incident,
    IngestionResult,
    TriageResult,
)


class TelemetryIngestor(Protocol):
    def ingest(
        self,
        payload: bytes,
        *,
        format: Literal["csv", "jsonl"],
        dataset_kind: DatasetKind,
        dataset_id: str,
        source: str,
        field_mapping: Mapping[str, str],
    ) -> IngestionResult:
        """Store original input, normalize valid records and quarantine invalid ones."""


class DetectionEngine(Protocol):
    def detect(self, events: Sequence[Event], *, detected_at: datetime) -> DetectionResult:
        """Analyze only supplied events; return alerts and incidents with evidence IDs."""


class TriageEngine(Protocol):
    def triage(
        self,
        incident: Incident,
        *,
        alerts: Sequence[Alert],
        evidence: Sequence[Event],
        generated_at: datetime,
    ) -> TriageResult:
        """Return an assessment tied to supplied evidence and the actual engine used."""


class RawTelemetryStore(Protocol):
    def put(
        self,
        payload: bytes,
        *,
        dataset_kind: DatasetKind,
        dataset_id: str,
        source: str,
        source_event_id: str | None,
    ) -> str:
        """Persist exact input bytes and return a durable opaque raw_ref."""

    def get(self, raw_ref: str) -> bytes:
        """Return the exact bytes originally passed to put."""


class SocRepository(Protocol):
    def put_events(self, events: list[Event]) -> None: ...

    def list_events(
        self,
        *,
        dataset_kind: DatasetKind,
        dataset_id: str,
        from_utc: datetime | None = None,
        to_utc: datetime | None = None,
        as_of: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Event]: ...

    def get_event(self, event_id: str, *, dataset_kind: DatasetKind, dataset_id: str) -> Event | None: ...

    def put_alerts(self, alerts: list[Alert]) -> None: ...

    def list_alerts(self, *, dataset_kind: DatasetKind, dataset_id: str) -> list[Alert]: ...

    def put_incidents(self, incidents: list[Incident]) -> None: ...

    def list_incidents(self, *, dataset_kind: DatasetKind, dataset_id: str) -> list[Incident]: ...

    def get_incident(self, incident_id: str, *, dataset_kind: DatasetKind, dataset_id: str) -> Incident | None: ...

    def put_triage_result(self, result: TriageResult) -> None: ...

    def list_triage_results(
        self, incident_id: str, *, dataset_kind: DatasetKind, dataset_id: str
    ) -> list[TriageResult]: ...

    def put_containment_action(self, action: ContainmentAction) -> None: ...

    def list_containment_actions(
        self, incident_id: str, *, dataset_kind: DatasetKind, dataset_id: str
    ) -> list[ContainmentAction]: ...
