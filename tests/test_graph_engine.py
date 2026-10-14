"""Forensic graph relationships are limited to supplied, resolvable evidence."""

from datetime import datetime, timedelta, timezone
import json

import pytest

from backend.detection import build_attack_graph
from backend.models import Alert, Event, Incident


BASE = datetime(2026, 10, 15, 10, tzinfo=timezone.utc)


def event(
    event_id: str,
    kind: str,
    attrs: dict | None = None,
    *,
    minute: int = 0,
    dataset_id: str = "case",
    source_event_id: str | None = None,
    source_record_number: int | None = None,
) -> Event:
    time = BASE + timedelta(minutes=minute)
    return Event(
        event_id=event_id,
        dataset_kind="synthetic",
        dataset_id=dataset_id,
        source="fixture.csv",
        source_event_id=source_event_id,
        source_timestamp=time.isoformat(),
        source_record_number=source_record_number,
        timestamp_utc=time,
        event_type=kind,
        raw_ref=f"raw:{event_id}",
        attributes=attrs or {},
    )


def alert(alert_id: str, event_ids: list[str], *, dataset_id: str = "case") -> Alert:
    return Alert(
        alert_id=alert_id,
        dataset_kind="synthetic",
        dataset_id=dataset_id,
        rule_id="test_rule",
        title="Test alert",
        description="Fixture",
        severity="high",
        detected_at=BASE + timedelta(hours=1),
        evidence_event_ids=event_ids,
    )


def incident(alert_ids: list[str], event_ids: list[str], *, dataset_id: str = "case") -> Incident:
    return Incident(
        incident_id="inc-1",
        dataset_kind="synthetic",
        dataset_id=dataset_id,
        title="Fixture incident",
        status="open",
        created_at=BASE + timedelta(hours=1),
        alert_ids=alert_ids,
        evidence_event_ids=event_ids,
    )


def rel(graph: dict, kind: str) -> list[dict]:
    return [edge for edge in graph["edges"] if edge["type"] == kind]


def test_observed_relationships_provenance_and_stable_ids():
    first = event("e1", "network_connection", {"user": "alice", "host": "h1", "destination_ip": "203.0.113.8", "outcome": "success"}, source_event_id="SRC-1", source_record_number=7)
    second = event("e2", "data_transfer", {"user": "alice", "host": "h1", "destination_ip": "203.0.113.8", "outcome": "success"}, minute=3)
    alert_item = alert("a1", ["e1", "e2"])
    case = incident(["a1"], ["e1", "e2"])
    graph = build_attack_graph(case, [alert_item], [second, first])
    assert graph == build_attack_graph(case, [alert_item, alert_item], [first, second, first])
    assert json.loads(json.dumps(graph)) == graph
    assert {node["type"] for node in graph["nodes"]} == {"incident", "alert", "event", "user", "host", "ip"}
    observed_on = rel(graph, "OBSERVED_ON")
    assert len(observed_on) == 1
    assert observed_on[0]["basis"] == "observed"
    assert observed_on[0]["evidence_event_ids"] == ["e1", "e2"]
    assert observed_on[0]["time_start_utc"] == first.timestamp_utc.isoformat()
    assert observed_on[0]["time_end_utc"] == second.timestamp_utc.isoformat()
    assert observed_on[0]["provenance"] == [
        {"event_id": "e1", "source": "fixture.csv", "raw_ref": "raw:e1", "source_timestamp": first.source_timestamp, "source_event_id": "SRC-1", "source_record_number": 7},
        {"event_id": "e2", "source": "fixture.csv", "raw_ref": "raw:e2", "source_timestamp": second.source_timestamp},
    ]
    assert len(rel(graph, "CONNECTED_TO")) == 1
    assert len(rel(graph, "EVIDENCE_FOR")) == 2
    assert rel(graph, "PART_OF")[0]["basis"] == "derived"
    assert all(edge["evidence_event_ids"] and edge["provenance"] for edge in graph["edges"])


def test_no_ip_file_or_process_from_unrelated_or_missing_fields():
    item = event("e1", "privilege_change", {"user": "alice", "host": "h1", "destination_ip": "203.0.113.1", "file_path": "/tmp/a", "process": "foo"})
    graph = build_attack_graph(incident(["a1"], ["e1"]), [alert("a1", ["e1"])], [item])
    assert {node["type"] for node in graph["nodes"]} == {"incident", "alert", "event", "user", "host"}
    assert rel(graph, "OBSERVED_ON")
    assert not rel(graph, "AUTHENTICATED_FROM")


def test_valid_file_process_and_ip_require_explicit_semantics():
    write = event("e1", "file_write", {"process": "editor", "file_path": "/tmp/a", "outcome": "success"})
    bad_ip = event("e2", "network_connection", {"host": "h1", "destination_ip": "not-an-ip"}, minute=1)
    graph = build_attack_graph(incident(["a1"], ["e1", "e2"]), [alert("a1", ["e1", "e2"])], [write, bad_ip])
    assert len(rel(graph, "HAS_PROCESS")) == 1
    assert len(rel(graph, "WROTE_FILE")) == 1
    assert not rel(graph, "CONNECTED_TO")
    assert not any(node["type"] == "ip" for node in graph["nodes"])


@pytest.mark.parametrize("kind", ["network_connection", "data_transfer"])
@pytest.mark.parametrize("outcome", ["denied", "failure", None])
def test_failed_or_unknown_connection_does_not_claim_completed_connection(kind, outcome):
    attrs = {"host": "h1", "destination_ip": "203.0.113.8"}
    if outcome is not None:
        attrs["outcome"] = outcome
    item = event("e1", kind, attrs)
    graph = build_attack_graph(incident(["a1"], ["e1"]), [alert("a1", ["e1"])], [item])
    assert rel(graph, "CONNECTED_TO") == []
    destination = rel(graph, "DESTINATION_IP")
    assert len(destination) == 1
    assert destination[0]["evidence_event_ids"] == ["e1"]
    assert destination[0]["provenance"] == [{"event_id": "e1", "source": "fixture.csv", "raw_ref": "raw:e1", "source_timestamp": item.source_timestamp}]


def test_completed_connection_excludes_denied_event_from_edge_evidence():
    good = event("ok", "network_connection", {"host": "h1", "destination_ip": "203.0.113.8", "outcome": "success"})
    denied = event("no", "network_connection", {"host": "h1", "destination_ip": "203.0.113.8", "outcome": "denied"}, minute=1)
    graph = build_attack_graph(incident(["a1"], ["ok", "no"]), [alert("a1", ["ok", "no"])], [good, denied])
    connection = rel(graph, "CONNECTED_TO")
    assert len(connection) == 1
    assert connection[0]["evidence_event_ids"] == ["ok"]
    assert connection[0]["provenance"] == [{"event_id": "ok", "source": "fixture.csv", "raw_ref": "raw:ok", "source_timestamp": good.source_timestamp}]


@pytest.mark.parametrize("kind,completed,attempted", [
    ("file_write", "WROTE_FILE", "ATTEMPTED_WRITE_FILE"),
    ("file_delete", "DELETED_FILE", "ATTEMPTED_DELETE_FILE"),
])
def test_file_action_requires_success_and_preserves_failed_target(kind, completed, attempted):
    good = event("ok", kind, {"file_path": "/tmp/a", "outcome": "success"})
    denied = event("no", kind, {"file_path": "/tmp/a", "outcome": "denied"}, minute=1)
    unknown = event("unknown", kind, {"file_path": "/tmp/a"}, minute=2)
    graph = build_attack_graph(
        incident(["a1"], ["ok", "no", "unknown"]),
        [alert("a1", ["ok", "no", "unknown"])],
        [good, denied, unknown],
    )
    assert [edge["evidence_event_ids"] for edge in rel(graph, completed)] == [["ok"]]
    assert [edge["evidence_event_ids"] for edge in rel(graph, attempted)] == [["no"]]
    assert [edge["evidence_event_ids"] for edge in rel(graph, "TARGET_FILE")] == [["unknown"]]
    assert all(edge["provenance"] for edge in rel(graph, completed) + rel(graph, attempted) + rel(graph, "TARGET_FILE"))


def test_as_of_omits_alerts_depending_on_future_evidence():
    earlier = event("e1", "privilege_change")
    later = event("e2", "backup_deleted", minute=15)
    case = incident(["a1", "a2"], ["e1", "e2"])
    alerts = [alert("a1", ["e1"]), alert("a2", ["e1", "e2"])]
    graph = build_attack_graph(case, alerts, [earlier, later], as_of=BASE + timedelta(minutes=10))
    assert graph["metadata"]["as_of"] == (BASE + timedelta(minutes=10)).isoformat()
    assert {node["label"] for node in graph["nodes"]} == {"inc-1", "a1", "e1"}
    assert all(edge["time_end_utc"] <= graph["metadata"]["as_of"] for edge in graph["edges"])
    before = build_attack_graph(case, alerts, [earlier, later], as_of=BASE - timedelta(seconds=1))
    assert before["nodes"] == before["edges"] == []
    with pytest.raises(ValueError, match="timezone"):
        build_attack_graph(case, alerts, [earlier, later], as_of=datetime(2026, 10, 15))


def test_partition_references_and_conflicting_duplicates_rejected():
    first = event("e1", "backup_deleted")
    case = incident(["a1"], ["e1"])
    good_alert = alert("a1", ["e1"])
    with pytest.raises(ValueError, match="partition"):
        build_attack_graph(case, [good_alert], [first, event("e2", "backup_deleted", dataset_id="other")])
    with pytest.raises(ValueError, match="partition"):
        build_attack_graph(case, [alert("a1", ["e1"], dataset_id="other")], [first])
    with pytest.raises(ValueError, match="unresolved incident"):
        build_attack_graph(case, [], [first])
    with pytest.raises(ValueError, match="unresolved incident"):
        build_attack_graph(case, [good_alert], [])
    with pytest.raises(ValueError, match="unresolved alert"):
        build_attack_graph(incident(["a1"], ["e1"]), [alert("a1", ["e2"])], [first])
    with pytest.raises(ValueError, match="conflicting duplicate"):
        build_attack_graph(case, [good_alert], [first, event("e1", "service_stopped")])
    with pytest.raises(ValueError, match="conflicting duplicate"):
        build_attack_graph(case, [good_alert, alert("a1", ["other"])], [first])


def test_node_limit_truncates_without_dangling_edges():
    first = event("e1", "network_connection", {"user": "alice", "host": "h1", "destination_ip": "203.0.113.8"})
    graph = build_attack_graph(incident(["a1"], ["e1"]), [alert("a1", ["e1"])], [first], max_nodes=3)
    assert graph["metadata"]["truncated"] is True
    assert graph["metadata"]["node_count"] == len(graph["nodes"]) == 3
    assert graph["metadata"]["edge_count"] == len(graph["edges"])
    assert graph["metadata"]["omitted_nodes"] > 0
    ids = {node["id"] for node in graph["nodes"]}
    assert all(edge["source"] in ids and edge["target"] in ids for edge in graph["edges"])
    assert {node["type"] for node in graph["nodes"]} == {"incident", "alert", "event"}
    with pytest.raises(ValueError, match="max_nodes"):
        build_attack_graph(incident(["a1"], ["e1"]), [alert("a1", ["e1"])], [first], max_nodes=0)
