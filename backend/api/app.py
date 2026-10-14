"""HTTP integration of the local SOC components.

Every collection request names a dataset partition.  This service only records
simulated containment; no live response executor is wired into the application.
"""

import base64
import binascii
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Response
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from backend.models import (
    Alert,
    ContainmentAction,
    DatasetKind,
    Event,
    Incident,
    IngestionResult,
    TriageResult,
)
from backend.ports import DetectionEngine, RawTelemetryStore, SocRepository, TelemetryIngestor, TriageEngine


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IngestionRequest(RequestModel):
    content_base64: str
    format: Literal["csv", "jsonl"]
    dataset_kind: DatasetKind
    dataset_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    field_mapping: dict[str, str]

    @field_validator("field_mapping")
    @classmethod
    def require_mapping(cls, value: dict[str, str]) -> dict[str, str]:
        if not {"source_timestamp", "event_type"}.issubset(value):
            raise ValueError("field_mapping requires source_timestamp and event_type")
        if any(not key or not column for key, column in value.items()):
            raise ValueError("field_mapping keys and columns must be nonempty")
        return value


class DetectionRequest(RequestModel):
    dataset_kind: DatasetKind
    dataset_id: str = Field(min_length=1)
    from_utc: AwareDatetime | None = None
    to_utc: AwareDatetime | None = None
    as_of: AwareDatetime | None = None


class DetectionResponse(RequestModel):
    alert_ids: list[str]
    incident_ids: list[str]
    persisted: bool
    alerts: list[Alert] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)


class SimulationRequest(RequestModel):
    action_type: str = Field(min_length=1)
    target: str = Field(min_length=1)
    evidence_event_ids: list[str] = Field(min_length=1)

    @field_validator("evidence_event_ids")
    @classmethod
    def unique_evidence(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_event_ids must be unique")
        return value


def _bad_reference(error: ValueError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(error))


def create_app(
    *,
    repository: SocRepository | None = None,
    raw_store: RawTelemetryStore | None = None,
    ingestor: TelemetryIngestor | None = None,
    detector: DetectionEngine | None = None,
    triage_engine: TriageEngine | None = None,
) -> FastAPI:
    """Create the application; injectable ports keep integration tests isolated."""
    if repository is None:
        from backend.storage import DuckDBSocRepository

        db_path = Path(os.getenv("GSEC_DUCKDB_PATH", "./data/sentinel.duckdb"))
        db_path.parent.mkdir(parents=True, exist_ok=True)
        repository = DuckDBSocRepository(db_path)
    if raw_store is None:
        from backend.storage import LocalRawTelemetryStore

        raw_store = LocalRawTelemetryStore(Path(os.getenv("GSEC_DATA_DIR", "./data")) / "raw")
    if ingestor is None:
        from backend.ingestion import CsvJsonlIngestor

        ingestor = CsvJsonlIngestor(repository, raw_store)
    if detector is None:
        from backend.detection import RuleBasedDetectionEngine

        detector = RuleBasedDetectionEngine()
    if triage_engine is None:
        from backend.ai import create_triage_engine

        triage_engine = create_triage_engine(
            enable_jev=os.getenv("GSEC_ENABLE_JEV", "").lower() in {"1", "true", "yes"},
            api_key=os.getenv("GSEC_JEV_API_KEY"),
        )

    app = FastAPI(title="GSEC Sentinel", version="0.1.0")

    @app.get("/health")
    async def health() -> dict[str, str]:
        try:
            repository.list_events(dataset_kind="synthetic", dataset_id="__health__", limit=1)
        except Exception as error:
            raise HTTPException(status_code=503, detail="storage unavailable") from error
        return {"status": "ok"}

    @app.post("/v1/ingestions", response_model=IngestionResult)
    async def ingest(request: IngestionRequest) -> IngestionResult:
        try:
            payload = base64.b64decode(request.content_base64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise HTTPException(status_code=422, detail="content_base64 is invalid") from error
        try:
            return ingestor.ingest(
                payload,
                format=request.format,
                dataset_kind=request.dataset_kind,
                dataset_id=request.dataset_id,
                source=request.source,
                field_mapping=request.field_mapping,
            )
        except ValueError as error:
            raise _bad_reference(error) from error

    @app.get("/v1/events", response_model=list[Event])
    async def events(
        dataset_kind: DatasetKind,
        dataset_id: str = Query(min_length=1),
        from_utc: AwareDatetime | None = None,
        to_utc: AwareDatetime | None = None,
        as_of: AwareDatetime | None = None,
        limit: int = Query(default=100, ge=1, le=10000),
        offset: int = Query(default=0, ge=0),
    ) -> list[Event]:
        if from_utc and to_utc and from_utc > to_utc:
            raise HTTPException(status_code=422, detail="from_utc must precede to_utc")
        return repository.list_events(
            dataset_kind=dataset_kind, dataset_id=dataset_id, from_utc=from_utc,
            to_utc=to_utc, as_of=as_of, limit=limit, offset=offset,
        )

    @app.get("/v1/events/{event_id}", response_model=Event)
    async def event(event_id: str, dataset_kind: DatasetKind, dataset_id: str = Query(min_length=1)) -> Event:
        found = repository.get_event(event_id, dataset_kind=dataset_kind, dataset_id=dataset_id)
        if found is None:
            raise HTTPException(status_code=404, detail="event not found")
        return found

    @app.get("/v1/events/{event_id}/raw")
    async def event_raw(event_id: str, dataset_kind: DatasetKind, dataset_id: str = Query(min_length=1)) -> Response:
        found = repository.get_event(event_id, dataset_kind=dataset_kind, dataset_id=dataset_id)
        if found is None:
            raise HTTPException(status_code=404, detail="event not found")
        try:
            payload = raw_store.get(found.raw_ref)
        except (KeyError, FileNotFoundError) as error:
            raise HTTPException(status_code=404, detail="raw telemetry not found") from error
        return Response(content=payload, media_type="application/octet-stream")

    @app.post("/v1/detections/run", response_model=DetectionResponse)
    async def run_detection(request: DetectionRequest) -> DetectionResponse:
        if request.from_utc and request.to_utc and request.from_utc > request.to_utc:
            raise HTTPException(status_code=422, detail="from_utc must precede to_utc")
        selected: list[Event] = []
        offset = 0
        while True:
            page = repository.list_events(
                dataset_kind=request.dataset_kind, dataset_id=request.dataset_id,
                from_utc=request.from_utc, to_utc=request.to_utc, as_of=request.as_of,
                limit=1000, offset=offset,
            )
            selected.extend(page)
            if len(page) < 1000:
                break
            offset += len(page)
        result = detector.detect(selected, detected_at=datetime.now(timezone.utc))
        selected_ids = {record.event_id for record in selected}
        alert_ids = {alert.alert_id for alert in result.alerts}
        for alert in result.alerts:
            if (alert.dataset_kind, alert.dataset_id) != (request.dataset_kind, request.dataset_id):
                raise HTTPException(status_code=500, detail="detector returned cross-partition alert")
            if not set(alert.evidence_event_ids).issubset(selected_ids):
                raise HTTPException(status_code=500, detail="detector returned evidence outside selected events")
        for incident in result.incidents:
            if (incident.dataset_kind, incident.dataset_id) != (request.dataset_kind, request.dataset_id):
                raise HTTPException(status_code=500, detail="detector returned cross-partition incident")
            if not set(incident.evidence_event_ids).issubset(selected_ids) or not set(incident.alert_ids).issubset(alert_ids):
                raise HTTPException(status_code=500, detail="detector returned invalid incident references")
        # Partial and historical runs are read-only views. Persisting their
        # incidents would create competing versions of the current investigation.
        persisted = request.as_of is None and request.from_utc is None and request.to_utc is None
        if persisted:
            try:
                repository.put_alerts(result.alerts)
                repository.put_incidents(result.incidents)
            except ValueError as error:
                raise _bad_reference(error) from error
        return DetectionResponse(
            alert_ids=[a.alert_id for a in result.alerts],
            incident_ids=[i.incident_id for i in result.incidents],
            persisted=persisted,
            alerts=[] if persisted else result.alerts,
            incidents=[] if persisted else result.incidents,
        )

    @app.get("/v1/alerts", response_model=list[Alert])
    async def alerts(dataset_kind: DatasetKind, dataset_id: str = Query(min_length=1)) -> list[Alert]:
        return repository.list_alerts(dataset_kind=dataset_kind, dataset_id=dataset_id)

    @app.get("/v1/incidents", response_model=list[Incident])
    async def incidents(dataset_kind: DatasetKind, dataset_id: str = Query(min_length=1)) -> list[Incident]:
        return repository.list_incidents(dataset_kind=dataset_kind, dataset_id=dataset_id)

    def get_incident_or_404(incident_id: str, dataset_kind: DatasetKind, dataset_id: str) -> Incident:
        found = repository.get_incident(incident_id, dataset_kind=dataset_kind, dataset_id=dataset_id)
        if found is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return found

    def resolve_incident(incident: Incident) -> tuple[list[Alert], list[Event]]:
        partition = {"dataset_kind": incident.dataset_kind, "dataset_id": incident.dataset_id}
        available = {alert.alert_id: alert for alert in repository.list_alerts(**partition)}
        linked_alerts = [available[alert_id] for alert_id in incident.alert_ids if alert_id in available]
        evidence = [repository.get_event(event_id, **partition) for event_id in incident.evidence_event_ids]
        if len(linked_alerts) != len(incident.alert_ids) or any(record is None for record in evidence):
            raise HTTPException(status_code=500, detail="incident references are inconsistent")
        return linked_alerts, sorted(evidence, key=lambda item: (item.timestamp_utc, item.event_id))

    @app.get("/v1/incidents/{incident_id}")
    async def incident_detail(incident_id: str, dataset_kind: DatasetKind, dataset_id: str = Query(min_length=1)) -> dict:
        found = get_incident_or_404(incident_id, dataset_kind, dataset_id)
        linked_alerts, evidence = resolve_incident(found)
        partition = {"dataset_kind": dataset_kind, "dataset_id": dataset_id}
        return {
            "incident": found,
            "alerts": linked_alerts,
            "events": evidence,
            "triage_results": repository.list_triage_results(incident_id, **partition),
            "containment_actions": repository.list_containment_actions(incident_id, **partition),
        }

    @app.get("/v1/incidents/{incident_id}/graph")
    async def incident_graph(
        incident_id: str,
        dataset_kind: DatasetKind,
        dataset_id: str = Query(min_length=1),
        as_of: AwareDatetime | None = None,
        max_nodes: int = Query(default=120, ge=1, le=250),
    ) -> dict:
        """Build an evidence graph from one partition and one incident.

        Historical graphs use a fresh, read-only detection snapshot.  They do
        not read persisted alerts as though those alerts existed at ``as_of``.
        """
        from backend.detection import build_attack_graph

        partition = {"dataset_kind": dataset_kind, "dataset_id": dataset_id}
        if as_of is None:
            found = get_incident_or_404(incident_id, dataset_kind, dataset_id)
            linked_alerts, evidence = resolve_incident(found)
            return build_attack_graph(found, linked_alerts, evidence, max_nodes=max_nodes)

        cutoff = as_of.astimezone(timezone.utc)
        selected: list[Event] = []
        offset = 0
        while True:
            page = repository.list_events(**partition, as_of=cutoff, limit=1000, offset=offset)
            selected.extend(page)
            if len(page) < 1000:
                break
            offset += len(page)
        if any((event.dataset_kind, event.dataset_id) != (dataset_kind, dataset_id)
               or event.timestamp_utc > cutoff for event in selected):
            raise HTTPException(status_code=500, detail="repository returned events outside graph snapshot")

        snapshot = detector.detect(selected, detected_at=cutoff)
        by_event = {event.event_id: event for event in selected}
        by_alert = {alert.alert_id: alert for alert in snapshot.alerts}
        by_incident = {incident.incident_id: incident for incident in snapshot.incidents}
        for alert in snapshot.alerts:
            if (alert.dataset_kind, alert.dataset_id) != (dataset_kind, dataset_id) or not set(alert.evidence_event_ids) <= by_event.keys():
                raise HTTPException(status_code=500, detail="detector returned invalid graph alert evidence")
        for incident in snapshot.incidents:
            if ((incident.dataset_kind, incident.dataset_id) != (dataset_kind, dataset_id)
                    or not set(incident.evidence_event_ids) <= by_event.keys()
                    or not set(incident.alert_ids) <= by_alert.keys()):
                raise HTTPException(status_code=500, detail="detector returned invalid graph incident evidence")

        found = by_incident.get(incident_id)
        if found is None:
            # A current incident can acquire a different ID as later alerts
            # arrive. Resolve its historical form only from its own evidence.
            current = repository.get_incident(incident_id, **partition)
            if current is None:
                raise HTTPException(status_code=404, detail="incident not found at selected time")
            candidates = [
                candidate for candidate in snapshot.incidents
                if set(candidate.evidence_event_ids) <= set(current.evidence_event_ids)
            ]
            if len(candidates) != 1:
                return {
                    "nodes": [], "edges": [],
                    "metadata": {
                        **partition, "incident_id": incident_id,
                        "as_of": cutoff.isoformat(), "node_count": 0, "edge_count": 0,
                        "total_nodes": 0, "total_edges": 0,
                        "returned_nodes": 0, "returned_edges": 0,
                        "omitted_nodes": 0, "truncated": False,
                        "limitations": ["No hay una versión inequívoca de este incidente en el instante seleccionado."],
                    },
                }
            found = candidates[0]

        linked_alerts = [by_alert[alert_id] for alert_id in found.alert_ids]
        evidence = [by_event[event_id] for event_id in found.evidence_event_ids]
        graph = build_attack_graph(found, linked_alerts, evidence, as_of=cutoff, max_nodes=max_nodes)
        graph["metadata"]["requested_incident_id"] = incident_id
        return graph

    @app.post("/v1/incidents/{incident_id}/triage", response_model=TriageResult)
    async def triage(incident_id: str, dataset_kind: DatasetKind, dataset_id: str = Query(min_length=1)) -> TriageResult:
        found = get_incident_or_404(incident_id, dataset_kind, dataset_id)
        linked_alerts, evidence = resolve_incident(found)
        generated_at = datetime.now(timezone.utc)
        try:
            result = triage_engine.triage(found, alerts=linked_alerts, evidence=evidence, generated_at=generated_at)
        except Exception:
            from backend.ai import DeterministicTriageEngine

            result = DeterministicTriageEngine().triage(
                found, alerts=linked_alerts, evidence=evidence, generated_at=generated_at
            )
        if result.incident_id != found.incident_id or not set(result.evidence_event_ids).issubset(set(found.evidence_event_ids)):
            raise HTTPException(status_code=500, detail="triage returned invalid references")
        try:
            repository.put_triage_result(result)
        except ValueError as error:
            raise _bad_reference(error) from error
        return result

    @app.post("/v1/incidents/{incident_id}/containment/simulate", response_model=ContainmentAction)
    async def simulate(
        incident_id: str,
        request: SimulationRequest,
        dataset_kind: DatasetKind,
        dataset_id: str = Query(min_length=1),
    ) -> ContainmentAction:
        found = get_incident_or_404(incident_id, dataset_kind, dataset_id)
        if not set(request.evidence_event_ids).issubset(set(found.evidence_event_ids)):
            raise HTTPException(status_code=422, detail="evidence must belong to this incident")
        action = ContainmentAction(
            action_id=f"sim-{uuid4().hex}", incident_id=incident_id,
            action_type=request.action_type, target=request.target,
            mode="simulation", status="simulated", requested_at=datetime.now(timezone.utc),
            evidence_event_ids=request.evidence_event_ids,
        )
        try:
            repository.put_containment_action(action)
        except ValueError as error:
            raise _bad_reference(error) from error
        return action

    return app


class _LazyApp:
    """Avoid opening the default DuckDB file when importing the app factory."""

    def __init__(self) -> None:
        self._instance: FastAPI | None = None

    async def __call__(self, scope, receive, send) -> None:
        if self._instance is None:
            self._instance = create_app()
        await self._instance(scope, receive, send)


app = _LazyApp()
