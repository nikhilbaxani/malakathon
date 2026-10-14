"""Positive, negative, isolation and replay-boundary checks for local rules."""

from datetime import datetime, timedelta, timezone

import pytest

from backend.detection import RuleBasedDetectionEngine
from backend.detection.rules import EXFIL_RULE, PRIVILEGE_RULE, SABOTAGE_RULE
from backend.models import Event


BASE = datetime(2026, 10, 15, 10, tzinfo=timezone.utc)
ENGINE = RuleBasedDetectionEngine()


def event(
    event_id: str,
    kind: str,
    attrs: dict,
    *,
    minute: int = 0,
    dataset_id: str = "sample",
    dataset_kind: str = "synthetic",
) -> Event:
    time = BASE + timedelta(minutes=minute)
    return Event(
        event_id=event_id,
        dataset_id=dataset_id,
        dataset_kind=dataset_kind,
        source="test fixture",
        source_timestamp=time.isoformat(),
        timestamp_utc=time,
        event_type=kind,
        raw_ref=f"raw:{event_id}",
        attributes=attrs,
    )


def entity(**attrs: object) -> dict:
    return {"user": "alice", "host": "host-1", **attrs}


def detect(events: list[Event]):
    return ENGINE.detect(events, detected_at=BASE + timedelta(hours=1))


def test_privilege_escalation_requires_successful_transition_to_admin():
    matched = event("p1", "privilege_change", entity(outcome="success", old_role="user", new_role="admin"))
    failed = event("p2", "privilege_change", entity(outcome="failure", old_role="user", new_role="admin"))
    already_admin = event("p3", "privilege_change", entity(outcome="success", old_role="admin", new_role="root"))
    empty_role = event("p4", "privilege_change", entity(outcome="success", old_role=" ", new_role="admin"))
    result = detect([failed, already_admin, empty_role, matched])
    assert [(a.rule_id, a.evidence_event_ids) for a in result.alerts] == [(PRIVILEGE_RULE, ["p1"])]
    assert result.incidents[0].evidence_event_ids == ["p1"]
    assert result.incidents[0].alert_ids == [result.alerts[0].alert_id]
    assert "Hecho:" in result.alerts[0].description
    assert "Hipótesis:" in result.alerts[0].description


def test_exfiltration_correlates_only_same_user_host_and_ten_minutes():
    outbound = entity(direction="outbound", destination_scope="external", bytes=6 * 1024 * 1024)
    events = [
        event("x1", "data_transfer", outbound),
        event("x2", "data_transfer", outbound, minute=9),
        event("other-host", "data_transfer", {**outbound, "host": "host-2"}, minute=5),
        event("late", "data_transfer", outbound, minute=30),
    ]
    result = detect(events)
    assert [(a.rule_id, a.evidence_event_ids) for a in result.alerts] == [(EXFIL_RULE, ["x1", "x2"])]
    assert result.incidents[0].evidence_event_ids == ["x1", "x2"]
    assert detect(events[:1]).alerts == []


def test_exfiltration_accepts_csv_decimal_byte_strings():
    outbound = entity(direction="outbound", destination_scope="external", bytes="6291456")
    result = detect([
        event("csv1", "data_transfer", outbound),
        event("csv2", "data_transfer", outbound, minute=4),
    ])
    assert [(a.rule_id, a.evidence_event_ids) for a in result.alerts] == [
        (EXFIL_RULE, ["csv1", "csv2"])
    ]
    assert "12582912 bytes" in result.alerts[0].description


def test_exfiltration_rejects_unconfirmed_destination_direction_and_bad_bytes():
    base = entity(bytes=20 * 1024 * 1024, direction="outbound", destination_scope="external")
    cases = [
        {**base, "direction": "inbound"},
        {**base, "destination_scope": "unknown"},
        {**base, "bytes": True},
        {**base, "host": ""},
        *({**base, "bytes": value} for value in [
            "", "0", "-20971520", "+20971520", "2e7", "20.0", " 20971520", "20971520 ", "２０９７１５２０"
        ]),
    ]
    assert detect([event(f"x{i}", "data_transfer", attrs) for i, attrs in enumerate(cases)]).alerts == []


@pytest.mark.parametrize("kind", ["backup_deleted", "audit_logging_disabled", "service_stopped"])
def test_sabotage_requires_success(kind):
    yes = event("s1", kind, entity(outcome="success"))
    no = event("s2", kind, entity(outcome="failure"))
    result = detect([yes, no])
    assert [(a.rule_id, a.evidence_event_ids) for a in result.alerts] == [(SABOTAGE_RULE, ["s1"])]


def test_alerts_cluster_into_incident_by_user_host_and_time():
    events = [
        event("p", "privilege_change", entity(outcome="success", old_role="user", new_role="admin")),
        event("s", "backup_deleted", entity(outcome="success"), minute=30),
        event("late", "backup_deleted", entity(outcome="success"), minute=91),
        event("other", "backup_deleted", {**entity(outcome="success"), "user": "bob"}, minute=35),
    ]
    result = detect(events)
    assert len(result.alerts) == 4
    assert sorted(i.evidence_event_ids for i in result.incidents) == [["late"], ["other"], ["p", "s"]]
    assert all(set(i.evidence_event_ids).issubset({e.event_id for e in events}) for i in result.incidents)
    assert detect(list(reversed(events))).model_dump() == result.model_dump()


def test_partition_and_duplicate_guards():
    first = event("p", "privilege_change", entity(outcome="success", old_role="user", new_role="admin"))
    assert len(detect([first, first]).alerts) == 1
    with pytest.raises(ValueError, match="partition"):
        detect([first, event("other", "backup_deleted", entity(outcome="success"), dataset_id="different")])
    with pytest.raises(ValueError, match="conflicting"):
        detect([first, event("p", "backup_deleted", entity(outcome="success"))])
    with pytest.raises(ValueError, match="timezone"):
        ENGINE.detect([first], detected_at=datetime(2026, 10, 15))
