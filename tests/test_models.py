"""Contract checks that can run before any storage or API implementation exists."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from backend.models import Alert, ContainmentAction, Event, Incident, IngestionResult, TriageResult


UTC = timezone.utc
LOCAL_TIME = datetime(2026, 10, 15, 12, 30, tzinfo=timezone(timedelta(hours=2)))


def event_data() -> dict:
    return {
        "event_id": "event-1",
        "dataset_id": "local-demo",
        "dataset_kind": "synthetic",
        "source": "fixture",
        "source_event_id": "original-001",
        "source_timestamp": "2026-10-15T12:30:00+02:00",
        "timestamp_utc": LOCAL_TIME,
        "event_type": "sample",
        "raw_ref": "raw-1",
        "attributes": {"attempts": 3, "tags": ["demo"]},
    }


def alert_data() -> dict:
    return {
        "alert_id": "alert-1",
        "dataset_id": "local-demo",
        "dataset_kind": "synthetic",
        "rule_id": "sample-rule",
        "title": "Sample alert",
        "description": "A test finding",
        "severity": "high",
        "detected_at": LOCAL_TIME,
        "evidence_event_ids": ["event-1"],
    }


def incident_data() -> dict:
    return {
        "incident_id": "incident-1",
        "dataset_id": "local-demo",
        "dataset_kind": "synthetic",
        "title": "Sample incident",
        "status": "open",
        "created_at": LOCAL_TIME,
        "alert_ids": ["alert-1"],
        "evidence_event_ids": ["event-1"],
    }


def triage_data() -> dict:
    return {
        "triage_id": "triage-1",
        "incident_id": "incident-1",
        "engine": "deterministic",
        "assessment": "needs_review",
        "summary": "Review the evidence",
        "rationale": "Only one event is available",
        "generated_at": LOCAL_TIME,
        "evidence_event_ids": ["event-1"],
    }


def action_data() -> dict:
    return {
        "action_id": "action-1",
        "incident_id": "incident-1",
        "action_type": "isolate_host",
        "target": "demo-host",
        "mode": "simulation",
        "status": "simulated",
        "requested_at": LOCAL_TIME,
        "evidence_event_ids": ["event-1"],
    }


@pytest.mark.parametrize(
    ("model", "data", "time_field"),
    [
        (Event, event_data, "timestamp_utc"),
        (Alert, alert_data, "detected_at"),
        (Incident, incident_data, "created_at"),
        (TriageResult, triage_data, "generated_at"),
        (ContainmentAction, action_data, "requested_at"),
    ],
)
def test_models_normalize_aware_time_and_reject_naive_or_extra_fields(model, data, time_field):
    record = model.model_validate(data())
    assert getattr(record, time_field) == datetime(2026, 10, 15, 10, 30, tzinfo=UTC)
    assert getattr(record, time_field).tzinfo is UTC

    with pytest.raises(ValidationError):
        model.model_validate({**data(), time_field: LOCAL_TIME.replace(tzinfo=None)})
    with pytest.raises(ValidationError):
        model.model_validate({**data(), "unexpected_field": "discard me"})


def test_event_preserves_source_identifiers_and_timestamp():
    record = Event.model_validate({**event_data(), "source_record_number": 2})
    assert record.source_event_id == "original-001"
    assert record.source_timestamp == "2026-10-15T12:30:00+02:00"
    assert record.source_record_number == 2
    assert record.dataset_kind == "synthetic"
    with pytest.raises(ValidationError):
        Event.model_validate({**event_data(), "dataset_kind": "unknown"})
    with pytest.raises(ValidationError):
        Event.model_validate({**event_data(), "attributes": {"bad": object()}})
    with pytest.raises(ValidationError):
        Event.model_validate({**event_data(), "source_record_number": 0})


def test_ingestion_result_keeps_quarantine_locator():
    result = IngestionResult.model_validate(
        {
            "batch_id": "batch-1",
            "dataset_id": "local-demo",
            "dataset_kind": "synthetic",
            "accepted_event_ids": ["event-1"],
            "errors": [{"record_number": 2, "raw_ref": "raw-file-1", "reason": "invalid timestamp"}],
        }
    )
    assert result.accepted_event_ids == ["event-1"]
    assert result.errors[0].record_number == 2
    assert result.errors[0].raw_ref == "raw-file-1"


@pytest.mark.parametrize(
    ("model", "data", "reference_field"),
    [
        (Alert, alert_data, "evidence_event_ids"),
        (Incident, incident_data, "alert_ids"),
        (Incident, incident_data, "evidence_event_ids"),
        (TriageResult, triage_data, "evidence_event_ids"),
        (ContainmentAction, action_data, "evidence_event_ids"),
    ],
)
def test_evidence_and_alert_references_are_nonempty_and_unique(model, data, reference_field):
    with pytest.raises(ValidationError):
        model.model_validate({**data(), reference_field: []})
    with pytest.raises(ValidationError):
        model.model_validate({**data(), reference_field: ["event-1", "event-1"]})


def test_live_action_requires_all_authorization_fields():
    live = {**action_data(), "mode": "live", "status": "approved"}
    with pytest.raises(ValidationError):
        ContainmentAction.model_validate(live)

    authorized = ContainmentAction.model_validate(
        {
            **live,
            "approval_ref": "approval-1",
            "authorized_by": "operator-1",
            "authorized_at": LOCAL_TIME,
        }
    )
    assert authorized.authorized_at == datetime(2026, 10, 15, 10, 30, tzinfo=UTC)


@pytest.mark.parametrize("status", ["approved", "executed"])
def test_simulation_cannot_claim_live_execution(status):
    with pytest.raises(ValidationError):
        ContainmentAction.model_validate({**action_data(), "status": status})
