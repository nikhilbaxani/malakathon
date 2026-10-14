"""Contract tests for the local data adapters."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.ingestion import CsvJsonlIngestor
from backend.models import Alert, ContainmentAction, Incident, TriageResult
from backend.storage import DuckDBSocRepository, LocalRawTelemetryStore


@pytest.fixture
def adapters(tmp_path):
    repository = DuckDBSocRepository(tmp_path / "soc.duckdb")
    raw = LocalRawTelemetryStore(tmp_path / "raw")
    yield CsvJsonlIngestor(repository, raw), repository, raw
    repository.close()


MAPPING = {"source_timestamp": "time", "event_type": "type", "source_event_id": "id"}


def ingest(ingestor, payload, *, format="jsonl", dataset_kind="synthetic", dataset_id="case"):
    return ingestor.ingest(
        payload, format=format, dataset_kind=dataset_kind, dataset_id=dataset_id,
        source="local", field_mapping=MAPPING,
    )


def test_jsonl_preserves_bytes_literals_attributes_and_deduplicates(adapters):
    ingestor, repo, raw = adapters
    payload = (b'{"time":"2026-10-14T13:30:00+02:00","type":"login","id":"upstream-1","user":"alice","bytes":42}\n'
               b'{"time":"2026-10-14T12:00:00Z","type":"logout","id":"upstream-2"}\n')
    result = ingest(ingestor, payload)
    assert not result.errors
    assert len(result.accepted_event_ids) == 2
    events = repo.list_events(dataset_kind="synthetic", dataset_id="case")
    assert events[0].source_event_id == "upstream-1"
    assert events[0].source_timestamp == "2026-10-14T13:30:00+02:00"
    assert events[0].timestamp_utc == datetime(2026, 10, 14, 11, 30, tzinfo=timezone.utc)
    assert events[0].attributes == {"user": "alice", "bytes": 42}
    assert events[0].source_record_number == 1
    assert raw.get(events[0].raw_ref) == payload
    assert raw.get_metadata(events[0].raw_ref) == {
        "dataset_kind": "synthetic", "dataset_id": "case", "source": "local", "source_event_id": None,
    }
    assert result.accepted_event_ids == ingest(ingestor, payload).accepted_event_ids
    assert len(repo.list_events(dataset_kind="synthetic", dataset_id="case")) == 2
    assert repo.list_events(dataset_kind="official", dataset_id="case") == []
    assert [e.event_id for e in repo.list_events(dataset_kind="synthetic", dataset_id="case", as_of=datetime(2026, 10, 14, 11, 40, tzinfo=timezone.utc))] == [events[0].event_id]
    assert [e.event_id for e in repo.list_events(dataset_kind="synthetic", dataset_id="case", limit=1, offset=1)] == [events[1].event_id]


def test_csv_quarantines_invalid_rows_and_keeps_original(adapters):
    ingestor, repo, raw = adapters
    payload = (b'time,type,id,host\r\n'
               b'2026-10-14T13:30:00+02:00,privilege_change,a,host1\r\n'
               b'2026-10-14T13:30:00,network,b,host2\r\n'
               b'bad,network,c,host3\r\n'
               b'2026-10-14T14:00:00+02:00,network,d\r\n')
    result = ingest(ingestor, payload, format="csv")
    assert len(result.accepted_event_ids) == 1
    assert [issue.record_number for issue in result.errors] == [2, 3, 4]
    assert {issue.raw_ref for issue in result.errors} == {repo.list_events(dataset_kind="synthetic", dataset_id="case")[0].raw_ref}
    assert raw.get(result.errors[0].raw_ref) == payload
    assert repo.list_events(dataset_kind="synthetic", dataset_id="case")[0].attributes == {"host": "host1"}


def test_jsonl_bad_record_is_independent_and_missing_timezone_is_quarantined(adapters):
    ingestor, repo, _ = adapters
    payload = b'not-json\n{"time":"2026-10-14T13:00:00","type":"x","id":"2"}\n{"time":"2026-10-14T13:00:00Z","type":"x","id":"3"}\n'
    result = ingest(ingestor, payload)
    assert [issue.record_number for issue in result.errors] == [1, 2]
    assert len(result.accepted_event_ids) == 1
    assert repo.get_event(result.accepted_event_ids[0], dataset_kind="synthetic", dataset_id="case") is not None


def test_conflicting_source_id_is_quarantined_and_raw_refs_are_opaque(adapters):
    ingestor, repo, raw = adapters
    first = b'{"time":"2026-10-14T13:00:00Z","type":"x","id":"same","value":1}\n'
    second = b'{"time":"2026-10-14T13:00:00Z","type":"x","id":"same","value":2}\n'
    assert len(ingest(ingestor, first).accepted_event_ids) == 1
    result = ingest(ingestor, second)
    assert not result.accepted_event_ids
    assert len(result.errors) == 1
    assert "conflicting events ID" in result.errors[0].reason
    assert raw.get(result.errors[0].raw_ref) == second
    with pytest.raises(ValueError):
        raw.get("../escape")
    assert len(repo.list_events(dataset_kind="synthetic", dataset_id="case")) == 1


def test_references_are_partition_checked_and_children_are_queryable(adapters):
    ingestor, repo, _ = adapters
    payload = b'{"time":"2026-10-14T13:00:00Z","type":"x","id":"1"}\n'
    event_id = ingest(ingestor, payload).accepted_event_ids[0]
    now = datetime(2026, 10, 14, tzinfo=timezone.utc)
    alert = Alert(alert_id="alert-1", dataset_kind="synthetic", dataset_id="case", rule_id="test", title="Test", description="Test", severity="high", detected_at=now, evidence_event_ids=[event_id])
    wrong = alert.model_copy(update={"alert_id": "wrong", "dataset_kind": "official"})
    with pytest.raises(ValueError):
        repo.put_alerts([alert, wrong])
    assert repo.list_alerts(dataset_kind="synthetic", dataset_id="case") == []
    repo.put_alerts([alert])
    incident = Incident(incident_id="incident-1", dataset_kind="synthetic", dataset_id="case", title="Test", status="open", created_at=now, alert_ids=[alert.alert_id], evidence_event_ids=[event_id])
    repo.put_incidents([incident])
    assert repo.get_incident("incident-1", dataset_kind="official", dataset_id="case") is None
    triage = TriageResult(triage_id="triage-1", incident_id=incident.incident_id, engine="deterministic", assessment="needs_review", summary="Review", rationale="Evidence", generated_at=now, evidence_event_ids=[event_id])
    repo.put_triage_result(triage)
    action = ContainmentAction(action_id="action-1", incident_id=incident.incident_id, action_type="isolate", target="host", mode="simulation", status="simulated", requested_at=now, evidence_event_ids=[event_id])
    repo.put_containment_action(action)
    assert repo.list_triage_results(incident.incident_id, dataset_kind="synthetic", dataset_id="case") == [triage]
    assert repo.list_containment_actions(incident.incident_id, dataset_kind="synthetic", dataset_id="case") == [action]
    assert repo.list_containment_actions(incident.incident_id, dataset_kind="official", dataset_id="case") == []


def test_reopen_persists_events_and_rejects_naive_query_time(tmp_path):
    db_path = tmp_path / "soc.duckdb"
    repo = DuckDBSocRepository(db_path)
    raw = LocalRawTelemetryStore(tmp_path / "raw")
    event_id = ingest(CsvJsonlIngestor(repo, raw), b'{"time":"2026-10-14T13:00:00Z","type":"x","id":"1"}\n').accepted_event_ids[0]
    repo.close()
    reopened = DuckDBSocRepository(db_path)
    assert reopened.get_event(event_id, dataset_kind="synthetic", dataset_id="case") is not None
    with pytest.raises(ValueError):
        reopened.list_events(dataset_kind="synthetic", dataset_id="case", as_of=datetime(2026, 10, 14))
    reopened.close()


def test_repeated_detection_ids_keep_first_timestamps_but_detect_conflicts(adapters):
    ingestor, repo, _ = adapters
    event_id = ingest(ingestor, b'{"time":"2026-10-14T13:00:00Z","type":"x","id":"1"}\n').accepted_event_ids[0]
    now = datetime(2026, 10, 14, tzinfo=timezone.utc)
    alert = Alert(alert_id="stable-alert", dataset_kind="synthetic", dataset_id="case", rule_id="rule", title="Test", description="Observed", severity="high", detected_at=now, evidence_event_ids=[event_id])
    incident = Incident(incident_id="stable-incident", dataset_kind="synthetic", dataset_id="case", title="Test", status="open", created_at=now, alert_ids=[alert.alert_id], evidence_event_ids=[event_id])
    repo.put_alerts([alert])
    repo.put_incidents([incident])
    repo.put_alerts([alert.model_copy(update={"detected_at": now + timedelta(hours=1)})])
    repo.put_incidents([incident.model_copy(update={"created_at": now + timedelta(hours=1)})])
    assert repo.list_alerts(dataset_kind="synthetic", dataset_id="case") == [alert]
    assert repo.list_incidents(dataset_kind="synthetic", dataset_id="case") == [incident]
    with pytest.raises(ValueError):
        repo.put_alerts([alert.model_copy(update={"severity": "critical", "detected_at": now + timedelta(hours=1)})])
    with pytest.raises(ValueError):
        repo.put_incidents([incident.model_copy(update={"evidence_event_ids": ["different"]})])
