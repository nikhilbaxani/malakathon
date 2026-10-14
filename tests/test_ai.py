"""Offline tests for evidence-bound triage and the optional provider boundary."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from backend.ai import DeterministicTriageEngine, JevTriageEngine, create_triage_engine
from backend.models import Alert, Event, Incident


AT = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)


def records(kind: str = "synthetic") -> tuple[Incident, list[Alert], list[Event]]:
    event = Event(
        event_id="event-sensitive-123",
        dataset_id="batch-1",
        dataset_kind=kind,
        source="secret-source",
        source_timestamp=AT.isoformat(),
        timestamp_utc=AT,
        event_type="sensitive-event-type",
        raw_ref="secret-raw-ref",
        attributes={"token": "DO-NOT-EXPORT"},
    )
    alert = Alert(
        alert_id="alert-1",
        dataset_id="batch-1",
        dataset_kind=kind,
        rule_id="sensitive-rule-id",
        title="secret alert title",
        description="secret description",
        severity="high",
        detected_at=AT,
        evidence_event_ids=[event.event_id],
    )
    incident = Incident(
        incident_id="incident-1",
        dataset_id="batch-1",
        dataset_kind=kind,
        title="secret incident title",
        status="open",
        created_at=AT,
        alert_ids=[alert.alert_id],
        evidence_event_ids=[event.event_id],
    )
    return incident, [alert], [event]


def test_deterministic_triage_is_repeatable_and_evidence_bound() -> None:
    incident, alerts, evidence = records()
    engine = DeterministicTriageEngine()
    first = engine.triage(incident, alerts=alerts, evidence=evidence, generated_at=AT)
    second = engine.triage(incident, alerts=alerts, evidence=evidence, generated_at=AT)
    assert first == second
    assert first.engine == "deterministic"
    assert first.assessment == "needs_review"
    assert first.evidence_event_ids == [evidence[0].event_id]
    assert "high" in first.summary
    assert "secret" not in first.summary + first.rationale
    assert engine.triage(
        incident, alerts=alerts, evidence=evidence, generated_at=AT + timedelta(hours=2)
    ).triage_id != first.triage_id


def test_triage_rejects_missing_cross_partition_and_naive_evidence() -> None:
    incident, alerts, evidence = records()
    engine = DeterministicTriageEngine()
    with pytest.raises(ValueError, match="evidence must resolve"):
        engine.triage(incident, alerts=alerts, evidence=[], generated_at=AT)
    with pytest.raises(ValueError, match="alert belongs"):
        engine.triage(
            incident,
            alerts=[alerts[0].model_copy(update={"dataset_id": "other"})],
            evidence=evidence,
            generated_at=AT,
        )
    with pytest.raises(ValueError, match="timezone"):
        engine.triage(incident, alerts=alerts, evidence=evidence, generated_at=AT.replace(tzinfo=None))


def test_factory_defaults_to_offline_even_with_key() -> None:
    assert isinstance(create_triage_engine(), DeterministicTriageEngine)
    assert isinstance(create_triage_engine(api_key="unused"), DeterministicTriageEngine)
    assert isinstance(create_triage_engine(enable_jev=True), DeterministicTriageEngine)


def test_mocked_jev_receives_only_synthetic_aggregate_counts() -> None:
    incident, alerts, evidence = records()
    sdk = Mock()
    sdk.system_one.return_value = SimpleNamespace(
        choices={"review_priority": SimpleNamespace(choice="urgent_review")}
    )
    manager = Mock()
    manager.__enter__ = Mock(return_value=sdk)
    manager.__exit__ = Mock(return_value=False)
    factory = Mock(return_value=manager)
    engine = create_triage_engine(
        enable_jev=True, api_key="test-key", timeout=1.5, client_factory=factory
    )
    assert isinstance(engine, JevTriageEngine)
    result = engine.triage(incident, alerts=alerts, evidence=evidence, generated_at=AT)
    assert result.engine == "jev"
    assert result.assessment == "needs_review"
    assert "urgente" in result.summary
    assert result.evidence_event_ids == incident.evidence_event_ids
    factory.assert_called_once_with("test-key", 1.5)
    call = sdk.system_one.call_args
    assert call.kwargs["timeout"] == 1.5
    assert call.kwargs["state"] == {
        "alert_count": 1,
        "severity_counts": {"low": 0, "medium": 0, "high": 1, "critical": 0},
    }
    payload = str(call.kwargs)
    for secret in ("DO-NOT-EXPORT", "secret", "event-sensitive-123", "sensitive-rule-id"):
        assert secret not in payload


@pytest.mark.parametrize("failure", [TimeoutError("slow"), RuntimeError("provider error")])
def test_provider_failure_falls_back_without_exposing_error(failure: Exception) -> None:
    incident, alerts, evidence = records()
    factory = Mock(side_effect=failure)
    result = JevTriageEngine(api_key="test-key", client_factory=factory).triage(
        incident, alerts=alerts, evidence=evidence, generated_at=AT
    )
    assert result.engine == "deterministic"
    assert result.assessment == "needs_review"
    assert str(failure) not in result.rationale


def test_official_data_never_calls_provider() -> None:
    incident, alerts, evidence = records("official")
    factory = Mock(side_effect=AssertionError("must remain offline"))
    result = JevTriageEngine(api_key="test-key", client_factory=factory).triage(
        incident, alerts=alerts, evidence=evidence, generated_at=AT
    )
    assert result.engine == "deterministic"
    factory.assert_not_called()


def test_invalid_jev_choice_falls_back() -> None:
    incident, alerts, evidence = records()
    sdk = Mock()
    sdk.system_one.return_value = SimpleNamespace(
        choices={"review_priority": SimpleNamespace(choice="unverified")}
    )
    manager = Mock()
    manager.__enter__ = Mock(return_value=sdk)
    manager.__exit__ = Mock(return_value=False)
    result = JevTriageEngine(api_key="test-key", client_factory=lambda *_: manager).triage(
        incident, alerts=alerts, evidence=evidence, generated_at=AT
    )
    assert result.engine == "deterministic"


def test_official_sdk_factory_uses_fixed_host_timeout_and_no_retries() -> None:
    from backend.ai import _official_client

    fake_retry = Mock(return_value="no-retries")
    fake_client = Mock(return_value="client")
    sdk = SimpleNamespace(RetryPolicy=fake_retry, TypeSafeClient=fake_client)
    with patch.dict("sys.modules", {"typesafe_sdk": sdk}):
        assert _official_client("test-key", 2.5) == "client"
    fake_retry.assert_called_once_with(max_retries=0)
    fake_client.assert_called_once_with(
        api_key="test-key",
        base_url="https://api.typesafe.ai",
        model="jev-latest",
        timeout=2.5,
        retry="no-retries",
    )
