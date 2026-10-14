"""Contract-level checks for HTTP requests and replay evidence boundaries."""

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from frontend.api import SocApi
from frontend.replay import detection_results_until, events_until, timeline


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def event(event_id, timestamp):
    return {"event_id": event_id, "timestamp_utc": timestamp, "event_type": "test", "source": "fixture"}


def test_replay_sends_cutoff_on_every_event_page_and_filters_late_server_data(monkeypatch):
    requests = []
    first = [event(f"e{number}", "2026-10-14T09:00:00Z") for number in range(2)]
    second = [event("late", "2026-10-14T11:00:00Z")]

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return FakeResponse(first if len(requests) == 1 else second)

    monkeypatch.setattr("frontend.api.urlopen", fake_urlopen)
    cutoff = datetime(2026, 10, 14, 10, tzinfo=timezone.utc)
    result = SocApi("http://localhost:8000").all_events("synthetic", "demo", as_of=cutoff, page_size=2)

    assert [item["event_id"] for item in events_until(result, cutoff)] == ["e0", "e1"]
    for request, timeout in requests:
        params = parse_qs(urlparse(request.full_url).query)
        assert params["as_of"] == [cutoff.isoformat()]
        assert params["dataset_kind"] == ["synthetic"]
        assert params["dataset_id"] == ["demo"]
        assert timeout == 10.0
    assert parse_qs(urlparse(requests[1][0].full_url).query)["offset"] == ["2"]


def test_replay_only_shows_results_of_that_run_with_visible_evidence():
    visible = [event("e1", "2026-10-14T09:00:00Z")]
    alerts = [
        {"alert_id": "a1", "evidence_event_ids": ["e1"]},
        {"alert_id": "a2", "evidence_event_ids": ["e2"]},
        {"alert_id": "old", "evidence_event_ids": ["e1"]},
    ]
    incidents = [
        {"incident_id": "i1", "alert_ids": ["a1"], "evidence_event_ids": ["e1"]},
        {"incident_id": "i2", "alert_ids": ["a2"], "evidence_event_ids": ["e2"]},
        {"incident_id": "i3", "alert_ids": ["old"], "evidence_event_ids": ["e1"]},
    ]
    selected_alerts, selected_incidents = detection_results_until(
        alerts, incidents, visible, ["a1", "a2"], ["i1", "i2", "i3"]
    )
    assert [item["alert_id"] for item in selected_alerts] == ["a1"]
    assert [item["incident_id"] for item in selected_incidents] == ["i1"]


def test_timeline_uses_event_time_order():
    ordered = timeline([event("later", "2026-10-14T11:00:00Z"), event("earlier", "2026-10-14T09:00:00+00:00")])
    assert [item["ID"] for item in ordered] == ["earlier", "later"]


def test_detection_replay_request_contains_partition_and_cutoff(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return FakeResponse({"alert_ids": [], "incident_ids": []})

    monkeypatch.setattr("frontend.api.urlopen", fake_urlopen)
    cutoff = datetime(2026, 10, 14, 10, tzinfo=timezone.utc)
    SocApi("http://localhost:8000").run_detection("synthetic", "demo", as_of=cutoff)
    assert requests[0].get_method() == "POST"
    assert json.loads(requests[0].data) == {
        "dataset_kind": "synthetic", "dataset_id": "demo", "as_of": cutoff.isoformat()
    }


def test_incident_actions_include_partition_in_query(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return FakeResponse({"mode": "simulation"})

    monkeypatch.setattr("frontend.api.urlopen", fake_urlopen)
    api = SocApi("http://localhost:8000")
    api.triage("incident/1", "synthetic", "demo")
    api.simulate("incident/1", "synthetic", "demo", "aislar_host", "host-1", ["e1"])

    for request in requests:
        params = parse_qs(urlparse(request.full_url).query)
        assert params == {"dataset_kind": ["synthetic"], "dataset_id": ["demo"]}
        assert "/incident%2F1/" in urlparse(request.full_url).path
    assert json.loads(requests[1].data) == {
        "action_type": "aislar_host", "target": "host-1", "evidence_event_ids": ["e1"]
    }


def test_current_console_hides_persisted_replay_results_until_complete_run(monkeypatch):
    from streamlit.testing.v1 import AppTest

    visible = event("e1", "2026-10-14T09:00:00Z")
    current_alert = {
        "alert_id": "a-current", "evidence_event_ids": ["e1"],
        "severity": "high", "title": "Prueba", "description": "Prueba", "rule_id": "rule-1",
        "detected_at": "2026-10-14T10:00:00Z",
    }
    replay_alert = {**current_alert, "alert_id": "a-replay"}
    current_incident = {
        "incident_id": "i-current", "alert_ids": ["a-current"], "evidence_event_ids": ["e1"],
        "status": "open", "title": "Prueba", "created_at": "2026-10-14T10:00:00Z",
    }
    replay_incident = {**current_incident, "incident_id": "i-replay", "alert_ids": ["a-replay"]}
    opened_incidents = []

    def fake_detail(_api, incident_id, _kind, _dataset_id):
        opened_incidents.append(incident_id)
        return {
            "incident": current_incident, "events": [visible], "alerts": [current_alert],
            "triage_results": [], "containment_actions": [],
        }

    monkeypatch.setattr(SocApi, "all_events", lambda *_args, **_kwargs: [visible])
    monkeypatch.setattr(SocApi, "alerts", lambda *_args, **_kwargs: [replay_alert, current_alert])
    monkeypatch.setattr(SocApi, "incidents", lambda *_args, **_kwargs: [replay_incident, current_incident])
    monkeypatch.setattr(SocApi, "run_detection", lambda *_args, **_kwargs: {
        "alert_ids": ["a-current"], "incident_ids": ["i-current"]
    })
    monkeypatch.setattr(SocApi, "incident_detail", fake_detail)
    monkeypatch.setattr(SocApi, "incident_graph", lambda *_args, **_kwargs: {
        "nodes": [], "edges": [], "metadata": {
            "dataset_kind": "synthetic", "dataset_id": "demo", "truncated": False,
            "limitations": [],
        },
    })

    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "frontend/app.py").run()
    app.sidebar.text_input[0].set_value("demo").run()
    assert not app.exception
    assert [metric.value for metric in app.metric] == ["1", "0", "0"]
    assert any("Ejecuta una detección completa" in caption.value for caption in app.get("caption"))

    app.button[0].click().run()
    assert not app.exception
    assert [metric.value for metric in app.metric] == ["1", "1", "1"]
    assert app.session_state["current_runs"][("synthetic", "demo")] == {
        "alert_ids": ["a-current"], "incident_ids": ["i-current"]
    }
    assert opened_incidents == ["i-current"]


def test_replay_renders_inline_results_without_persisted_collection_reads(monkeypatch):
    from streamlit.testing.v1 import AppTest

    early = event("e1", "2026-10-14T09:00:00Z")
    late = event("e2", "2026-10-14T11:00:00Z")
    alert = {
        "alert_id": "a1", "evidence_event_ids": ["e1"], "severity": "high",
        "title": "Prueba", "description": "Prueba", "rule_id": "rule-1",
        "detected_at": "2026-10-14T10:00:00Z",
    }
    incident = {
        "incident_id": "i1", "alert_ids": ["a1"], "evidence_event_ids": ["e1"],
        "status": "open", "title": "Prueba", "created_at": "2026-10-14T10:00:00Z",
    }
    calls = []

    def fake_events(_api, _kind, _dataset_id, *, as_of=None):
        calls.append(("events", as_of))
        return [early, late]

    def fake_detection(_api, _kind, _dataset_id, *, as_of=None):
        calls.append(("detection", as_of))
        return {
            "persisted": False, "alert_ids": ["a1"], "incident_ids": ["i1"],
            "alerts": [alert], "incidents": [incident],
        }

    def forbidden_collections(*_args, **_kwargs):
        raise AssertionError("Replay no debe leer colecciones persistidas")

    monkeypatch.setattr(SocApi, "all_events", fake_events)
    monkeypatch.setattr(SocApi, "run_detection", fake_detection)
    monkeypatch.setattr(SocApi, "alerts", forbidden_collections)
    monkeypatch.setattr(SocApi, "incidents", forbidden_collections)
    monkeypatch.setattr(SocApi, "incident_detail", forbidden_collections)

    def fake_graph(_api, _incident_id, _kind, _dataset_id, *, as_of=None, max_nodes=120):
        calls.append(("graph", as_of))
        return {
            "nodes": [], "edges": [], "metadata": {
                "dataset_kind": "synthetic", "dataset_id": "demo", "as_of": as_of.isoformat(),
                "truncated": False, "limitations": [],
            },
        }

    monkeypatch.setattr(SocApi, "incident_graph", fake_graph)

    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "frontend/app.py").run()
    app.sidebar.text_input[0].set_value("demo")
    app.sidebar.toggle[0].set_value(True)
    app.run()
    app.sidebar.date_input[0].set_value(datetime(2026, 10, 14).date())
    app.sidebar.time_input[0].set_value(datetime(2026, 10, 14, 10).time())
    app.run()
    assert not app.exception
    assert [metric.value for metric in app.metric] == ["1", "0", "0"]

    app.button[0].click().run()
    assert not app.exception
    assert [metric.value for metric in app.metric] == ["1", "1", "1"]
    assert any("Resultados transitorios" in caption.value for caption in app.get("caption"))
    assert any(name == "detection" and as_of.isoformat() == "2026-10-14T10:00:00+00:00" for name, as_of in calls)
    assert any(name == "graph" and as_of.isoformat() == "2026-10-14T10:00:00+00:00" for name, as_of in calls)
