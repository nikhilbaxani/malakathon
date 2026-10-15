"""Contract-level checks for HTTP requests and replay evidence boundaries."""

import json
import io
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from frontend.api import ApiError, SocApi
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


def test_raw_evidence_preserves_bytes_and_partition(monkeypatch):
    requests = []
    original = b'\xff\x00original\r\n{"source_id": "one"}\n'

    def fake_urlopen(request, timeout):
        requests.append(request)
        return io.BytesIO(original)

    monkeypatch.setattr("frontend.api.urlopen", fake_urlopen)
    result = SocApi("http://localhost:8000").raw_event("event/one", "synthetic", "demo")
    assert result == original
    request = requests[0]
    url = urlparse(request.full_url)
    assert request.get_method() == "GET"
    assert url.path.endswith("/event%2Fone/raw")
    assert parse_qs(url.query) == {"dataset_kind": ["synthetic"], "dataset_id": ["demo"]}


def test_raw_evidence_api_failure_is_reported(monkeypatch):
    from urllib.error import HTTPError
    import pytest

    def failed(request, timeout):
        raise HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(b'{"detail":"event not found"}'))

    monkeypatch.setattr("frontend.api.urlopen", failed)
    with pytest.raises(ApiError, match="404"):
        SocApi("http://localhost:8000").raw_event("missing", "official", "demo")


def test_current_console_hides_persisted_replay_results_until_complete_run(monkeypatch, kpi_values):
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
        "persisted": True, "alert_ids": ["a-current"], "incident_ids": ["i-current"]
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
    assert kpi_values(app) == ["1", "0", "0", "0"]
    assert any("DETECCIÓN PENDIENTE" in item.value for item in app.caption)
    assert any("Ejecuta una detección completa" in caption.value for caption in app.get("caption"))

    app.button[0].click().run()
    assert not app.exception
    assert kpi_values(app) == ["1", "1", "1", "1"]
    assert not any("DETECCIÓN PENDIENTE" in item.value for item in app.caption)
    assert len(app.get("vega_lite_chart")) == 1
    distribution = next(item.proto.body for item in app.get("html") if 'class="soc-distribution"' in item.proto.body)
    assert '1 alertas, distribución por severidad' in distribution
    assert app.session_state["current_runs"][("synthetic", "demo")] == {
        "persisted": True, "alert_ids": ["a-current"], "incident_ids": ["i-current"]
    }
    assert opened_incidents == []
    monkeypatch.setattr(SocApi, "all_events", lambda *_args, **_kwargs: [
        visible, event("e-new", "2026-10-14T12:00:00Z")])
    next(button for button in app.button if button.label == "Actualizar datos").click().run()
    assert not app.exception
    assert kpi_values(app)[0] == "2"
    assert any("HALLAZGOS PENDIENTES DE ACTUALIZAR" in item.value for item in app.info)
    next(button for button in app.button if button.label == "Investigar →").click().run()
    assert opened_incidents == ["i-current"]
    assert app.session_state["nav"] == "Investigation Workspace"


def test_replay_renders_inline_results_without_persisted_collection_reads(monkeypatch, kpi_values):
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
    assert kpi_values(app) == ["1", "0", "0", "0"]

    app.button[0].click().run()
    assert not app.exception
    assert kpi_values(app) == ["1", "1", "1", "1"]
    assert any("REPLAY hasta" in item.value for item in app.get("caption"))
    assert any(name == "detection" and as_of.isoformat() == "2026-10-14T10:00:00+00:00" for name, as_of in calls)
    assert not any(name == "graph" for name, _ in calls)
    app.sidebar.radio[0].set_value("Investigation Workspace").run()
    assert any(name == "graph" and as_of.isoformat() == "2026-10-14T10:00:00+00:00" for name, as_of in calls)


def test_event_snapshot_is_cached_until_refresh_and_replay_uses_another_key(monkeypatch):
    from streamlit.testing.v1 import AppTest

    calls = []

    def fake_events(_api, _kind, _dataset_id, *, as_of=None):
        calls.append(as_of)
        return [event("e1", "2026-10-14T09:00:00Z")]

    monkeypatch.setattr(SocApi, "all_events", fake_events)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "frontend/app.py").run()
    app.sidebar.text_input[0].set_value("demo").run()
    assert len(calls) == 1
    app.sidebar.radio[0].set_value("Threat Hunting").run()
    assert len(calls) == 1
    next(button for button in app.button if button.label == "Actualizar datos").click().run()
    assert len(calls) == 2
    app.sidebar.toggle[0].set_value(True).run()
    assert len(calls) == 3
    assert calls[-1] is not None


def test_console_api_error_can_be_retried_without_showing_previous_events(monkeypatch):
    from streamlit.testing.v1 import AppTest

    unavailable = [False]

    def fake_events(*_args, **_kwargs):
        if unavailable[0]:
            raise ApiError("HTTP 503: unavailable")
        return [event("e1", "2026-10-14T09:00:00Z")]

    monkeypatch.setattr(SocApi, "all_events", fake_events)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "frontend/app.py").run()
    app.sidebar.text_input[0].set_value("demo").run()
    app.sidebar.radio[0].set_value("Threat Hunting").run()
    assert not app.exception
    assert app.dataframe
    unavailable[0] = True
    next(button for button in app.button if button.label == "Actualizar datos").click().run()
    assert not app.exception
    assert app.error
    assert len(app.dataframe) == 0
    unavailable[0] = False
    next(button for button in app.button if button.label == "Actualizar datos").click().run()
    assert not app.exception
    assert app.dataframe
    assert not app.error


def test_response_requires_explicit_confirmation_before_simulation(monkeypatch):
    from streamlit.testing.v1 import AppTest

    visible = event("e1", "2026-10-14T09:00:00Z")
    alert = {
        "alert_id": "a1", "evidence_event_ids": ["e1"], "severity": "high", "title": "Prueba",
        "description": "Prueba", "rule_id": "rule-1", "detected_at": "2026-10-14T10:00:00Z",
    }
    incident = {
        "incident_id": "i1", "alert_ids": ["a1"], "evidence_event_ids": ["e1"],
        "status": "open", "title": "Prueba", "created_at": "2026-10-14T10:00:00Z",
    }
    simulation_calls = []
    triage_calls = []
    recorded_triage = []
    recorded_actions = []

    monkeypatch.setattr(SocApi, "all_events", lambda *_args, **_kwargs: [visible])
    monkeypatch.setattr(SocApi, "alerts", lambda *_args, **_kwargs: [alert])
    monkeypatch.setattr(SocApi, "incidents", lambda *_args, **_kwargs: [incident])
    monkeypatch.setattr(SocApi, "run_detection", lambda *_args, **_kwargs: {
        "persisted": True, "alert_ids": ["a1"], "incident_ids": ["i1"],
    })
    monkeypatch.setattr(SocApi, "incident_detail", lambda *_args, **_kwargs: {
        "incident": incident, "events": [visible], "alerts": [alert],
        "triage_results": recorded_triage, "containment_actions": recorded_actions,
    })

    def fake_simulate(_api, incident_id, kind, dataset_id, action_type, target, evidence_ids):
        simulation_calls.append((incident_id, kind, dataset_id, action_type, target, evidence_ids))
        result = {"mode": "simulation", "status": "simulated", "action_id": "sim-1",
                  "action_type": action_type, "target": target}
        recorded_actions.append(result)
        return result

    def fake_triage(_api, incident_id, kind, dataset_id):
        triage_calls.append((incident_id, kind, dataset_id))
        result = {"triage_id": "tri-1", "engine": "deterministic", "assessment": "needs_review",
                  "summary": "Revisión necesaria", "evidence_event_ids": ["e1"]}
        recorded_triage.append(result)
        return result

    monkeypatch.setattr(SocApi, "simulate", fake_simulate)
    monkeypatch.setattr(SocApi, "triage", fake_triage)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "frontend/app.py").run()
    app.sidebar.text_input[0].set_value("demo").run()
    next(button for button in app.button if button.label == "Ejecutar detección").click().run()
    app.sidebar.radio[0].set_value("Response Center").run()
    assert not simulation_calls
    next(item for item in app.selectbox if item.label == "Seleccionar incidente para respuesta").set_value("i1").run()
    next(item for item in app.text_input if item.label == "Tipo de acción").set_value("isolate_host")
    next(item for item in app.text_input if item.label == "Objetivo exacto").set_value("host-1")
    next(item for item in app.multiselect if item.label == "Evidencia que justifica la simulación").set_value(["e1"])
    next(button for button in app.button if button.label == "Registrar simulación").click().run()
    assert not simulation_calls
    next(item for item in app.checkbox if item.label.startswith("Confirmo")).set_value(True)
    next(button for button in app.button if button.label == "Registrar simulación").click().run()
    assert simulation_calls == [("i1", "synthetic", "demo", "isolate_host", "host-1", ["e1"])]
    assert not any("Sin acciones registradas" in caption.value for caption in app.get("caption"))
    assert any("mode=simulation" in message.value for message in app.get("success"))
    next(button for button in app.button if button.label == "Evaluar triage").click().run()
    assert triage_calls == [("i1", "synthetic", "demo")]
    assert not any("Sin triage registrado" in caption.value for caption in app.get("caption"))
    assert any("Triage registrado" in message.value for message in app.get("success"))
    app.sidebar.selectbox[0].set_value("official").run()
    assert not app.exception
    assert app.session_state["selected_incident"] is None
    assert len(simulation_calls) == 1
    assert len(triage_calls) == 1


def test_multiple_incidents_can_be_selected_and_shared_between_workspaces(monkeypatch):
    from streamlit.testing.v1 import AppTest

    visible = event("e1", "2026-10-14T09:00:00Z")
    alert = {"alert_id": "a1", "evidence_event_ids": ["e1"], "severity": "high",
             "title": "Alerta de prueba", "description": "Prueba", "rule_id": "r1",
             "detected_at": "2026-10-14T10:00:00Z"}
    incidents = [{"incident_id": value, "alert_ids": ["a1"], "evidence_event_ids": ["e1"],
                  "status": "open", "title": f"Incidente {value}", "created_at": "2026-10-14T10:00:00Z"}
                 for value in ("i1", "i2")]
    monkeypatch.setattr(SocApi, "all_events", lambda *_args, **_kwargs: [visible])
    monkeypatch.setattr(SocApi, "alerts", lambda *_args, **_kwargs: [alert])
    monkeypatch.setattr(SocApi, "incidents", lambda *_args, **_kwargs: incidents)
    monkeypatch.setattr(SocApi, "run_detection", lambda *_args, **_kwargs: {
        "persisted": True, "alert_ids": ["a1"], "incident_ids": ["i1", "i2"]})
    monkeypatch.setattr(SocApi, "incident_detail", lambda _api, incident_id, *_args: {
        "incident": next(item for item in incidents if item["incident_id"] == incident_id),
        "events": [visible], "alerts": [alert], "triage_results": [], "containment_actions": []})
    monkeypatch.setattr(SocApi, "incident_graph", lambda *_args, **_kwargs: {
        "nodes": [], "edges": [], "metadata": {"dataset_kind": "synthetic", "dataset_id": "demo"}})
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "frontend/app.py").run()
    app.sidebar.text_input[0].set_value("demo").run()
    next(button for button in app.button if button.label == "Ejecutar detección").click().run()
    app.sidebar.radio[0].set_value("Investigation Workspace").run()
    next(box for box in app.selectbox if box.label == "Incidente en investigación").set_value("i2").run()
    assert not app.exception
    assert app.session_state["selected_incident"] == "i2"
    next(button for button in app.button if button.label == "Evaluar respuesta →").click().run()
    assert next(box for box in app.selectbox if box.label == "Seleccionar incidente para respuesta").value == "i2"
    next(box for box in app.selectbox if box.label == "Seleccionar incidente para respuesta").set_value("i1").run()
    assert app.session_state["selected_incident"] == "i1"
    app.sidebar.radio[0].set_value("Investigation Workspace").run()
    assert not app.exception
    assert next(box for box in app.selectbox if box.label == "Incidente en investigación").value == "i1"
