"""Contract-level HTTP flow using explicitly synthetic local telemetry."""

import base64
import asyncio
import io
import json
from pathlib import Path
from urllib.parse import urlparse

import httpx

from backend.api.app import create_app
from backend.storage import DuckDBSocRepository, LocalRawTelemetryStore


class _Client:
    """Use ASGI directly; this environment cannot start AnyIO worker threads."""

    def __init__(self, app):
        self.app = app

    def request(self, method, path, **kwargs):
        async def call():
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(call())

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)


def test_synthetic_http_flow_and_replay(tmp_path, monkeypatch, kpi_values):
    # This is an invented test fixture, not a representation of an official feed.
    records = [
        {
            "id": "source-1", "timestamp": "2026-10-15T10:00:00+02:00", "type": "privilege_change",
            "user": "alice", "host": "host-1", "outcome": "success", "old_role": "user", "new_role": "admin",
        },
        {
            "id": "source-2", "timestamp": "2026-10-15T10:01:00+02:00", "type": "data_transfer",
            "user": "alice", "host": "host-1", "direction": "outbound",
            "destination_scope": "external", "bytes": 6 * 1024 * 1024,
        },
        {
            "id": "source-3", "timestamp": "2026-10-15T10:02:00+02:00", "type": "data_transfer",
            "user": "alice", "host": "host-1", "direction": "outbound",
            "destination_scope": "external", "bytes": 6 * 1024 * 1024,
        },
    ]
    payload = ("\n".join(json.dumps(row) for row in records) + "\n").encode()
    repository = DuckDBSocRepository(tmp_path / "events.duckdb")
    raw_store = LocalRawTelemetryStore(tmp_path / "raw")
    from backend.ingestion import CsvJsonlIngestor

    from backend.detection import RuleBasedDetectionEngine

    from backend.ai import DeterministicTriageEngine

    client = _Client(create_app(
        repository=repository, raw_store=raw_store,
        ingestor=CsvJsonlIngestor(repository, raw_store),
        detector=RuleBasedDetectionEngine(), triage_engine=DeterministicTriageEngine(),
    ))
    partition = {"dataset_kind": "synthetic", "dataset_id": "http-demo"}
    upload = client.post("/v1/ingestions", json={
        **partition, "format": "jsonl", "source": "local-test",
        "content_base64": base64.b64encode(payload).decode(),
        "field_mapping": {"source_timestamp": "timestamp", "event_type": "type", "source_event_id": "id"},
    })
    assert upload.status_code == 200, upload.text
    assert len(upload.json()["accepted_event_ids"]) == 3
    assert upload.json()["errors"] == []

    response = client.get("/v1/events", params=partition)
    assert response.status_code == 200, response.text
    events = response.json()
    assert {event["source_event_id"] for event in events} == {"source-1", "source-2", "source-3"}
    assert {event["source_timestamp"] for event in events} == {row["timestamp"] for row in records}
    assert all(event["timestamp_utc"].endswith("Z") for event in events)
    id_by_source = {event["source_event_id"]: event["event_id"] for event in events}
    raw = client.get(f"/v1/events/{id_by_source['source-1']}/raw", params=partition)
    assert raw.status_code == 200 and raw.content == payload
    assert client.get("/v1/events", params={"dataset_kind": "official", "dataset_id": "http-demo"}).json() == []

    cutoff = "2026-10-15T08:01:30Z"
    replay_events = client.get("/v1/events", params={**partition, "as_of": cutoff})
    assert replay_events.status_code == 200
    assert {event["source_event_id"] for event in replay_events.json()} == {"source-1", "source-2"}
    replay = client.post("/v1/detections/run", json={**partition, "as_of": cutoff})
    assert replay.status_code == 200, replay.text
    assert replay.json()["alert_ids"]
    assert replay.json()["persisted"] is False
    replay_alerts = replay.json()["alerts"]
    assert all(id_by_source["source-3"] not in alert["evidence_event_ids"] for alert in replay_alerts)
    assert client.get("/v1/alerts", params=partition).json() == []
    assert client.get("/v1/incidents", params=partition).json() == []
    assert client.get(f"/v1/incidents/{replay.json()['incident_ids'][0]}", params=partition).status_code == 404
    historical_graph = client.get(
        f"/v1/incidents/{replay.json()['incident_ids'][0]}/graph",
        params={**partition, "as_of": cutoff},
    )
    assert historical_graph.status_code == 200, historical_graph.text
    past = historical_graph.json()
    assert past["nodes"] and past["edges"]
    assert past["metadata"]["incident_id"] == replay.json()["incident_ids"][0]
    assert {event_id for edge in past["edges"] for event_id in edge["evidence_event_ids"]} <= {
        id_by_source["source-1"], id_by_source["source-2"]
    }
    assert all(edge["time_end_utc"] <= "2026-10-15T08:01:30+00:00" for edge in past["edges"])
    assert client.get("/v1/incidents", params=partition).json() == []

    full = client.post("/v1/detections/run", json=partition)
    assert full.status_code == 200, full.text
    assert full.json()["persisted"] is True
    assert full.json()["incident_ids"]
    alerts = client.get("/v1/alerts", params=partition).json()
    assert any(id_by_source["source-3"] in alert["evidence_event_ids"] for alert in alerts)
    assert all(set(alert["evidence_event_ids"]).issubset(set(id_by_source.values())) for alert in alerts)
    incident_id = full.json()["incident_ids"][0]
    detail = client.get(f"/v1/incidents/{incident_id}", params=partition)
    assert detail.status_code == 200, detail.text
    assert detail.json()["incident"]["incident_id"] == incident_id
    current_graph = client.get(f"/v1/incidents/{incident_id}/graph", params=partition)
    assert current_graph.status_code == 200, current_graph.text
    graph = current_graph.json()
    assert {node["type"] for node in graph["nodes"]} == {"incident", "alert", "event", "user", "host"}
    assert graph["metadata"]["dataset_id"] == partition["dataset_id"]
    assert {event_id for edge in graph["edges"] for event_id in edge["evidence_event_ids"]} == set(id_by_source.values())
    assert client.get(
        f"/v1/incidents/{incident_id}/graph",
        params={"dataset_kind": "official", "dataset_id": partition["dataset_id"]},
    ).status_code == 404
    assert client.get(f"/v1/incidents/{incident_id}/graph", params={**partition, "max_nodes": 0}).status_code == 422
    historical_from_current = client.get(
        f"/v1/incidents/{incident_id}/graph", params={**partition, "as_of": cutoff}
    )
    assert historical_from_current.status_code == 200, historical_from_current.text
    assert historical_from_current.json()["edges"] == past["edges"]
    assert historical_from_current.json()["metadata"]["requested_incident_id"] == incident_id
    before_first = client.get(
        f"/v1/incidents/{incident_id}/graph",
        params={**partition, "as_of": "2026-10-15T07:59:59Z"},
    )
    assert before_first.status_code == 200, before_first.text
    assert before_first.json()["nodes"] == before_first.json()["edges"] == []
    assert client.get(
        f"/v1/incidents/{incident_id}/graph",
        params={**partition, "as_of": "2026-10-15T08:01:30"},
    ).status_code == 422

    triage = client.post(f"/v1/incidents/{incident_id}/triage", params=partition)
    assert triage.status_code == 200, triage.text
    assert triage.json()["engine"] == "deterministic"
    assert set(triage.json()["evidence_event_ids"]).issubset(set(id_by_source.values()))
    incident_evidence = detail.json()["incident"]["evidence_event_ids"]
    simulation = client.post(
        f"/v1/incidents/{incident_id}/containment/simulate", params=partition,
        json={"action_type": "isolate_host", "target": "host-1", "evidence_event_ids": incident_evidence},
    )
    assert simulation.status_code == 200, simulation.text
    assert simulation.json()["mode"] == "simulation"
    assert simulation.json()["status"] == "simulated"
    persisted = client.get(f"/v1/incidents/{incident_id}", params=partition).json()
    assert persisted["triage_results"] and persisted["containment_actions"]
    assert len(client.get("/v1/incidents", params=partition).json()) == 1
    historical_again = client.post("/v1/detections/run", json={**partition, "as_of": cutoff})
    assert historical_again.status_code == 200 and historical_again.json()["persisted"] is False
    interval = client.post("/v1/detections/run", json={**partition, "to_utc": cutoff})
    assert interval.status_code == 200 and interval.json()["persisted"] is False
    assert len(client.get("/v1/incidents", params=partition).json()) == 1
    after_replay = client.get(f"/v1/incidents/{incident_id}", params=partition).json()
    assert after_replay["incident"] == persisted["incident"]
    assert after_replay["triage_results"] == persisted["triage_results"]
    assert after_replay["containment_actions"] == persisted["containment_actions"]

    # Drive the real Streamlit dashboard against this same ASGI application.
    from streamlit.testing.v1 import AppTest

    def asgi_urlopen(request, timeout):
        url = urlparse(request.full_url)
        response = client.request(
            request.get_method(), url.path + (f"?{url.query}" if url.query else ""),
            content=request.data,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200, response.text
        return io.BytesIO(response.content)

    monkeypatch.setattr("frontend.api.urlopen", asgi_urlopen)
    dashboard = AppTest.from_file(str(Path(__file__).parents[1] / "frontend" / "app.py"))
    dashboard.run(timeout=10)
    dashboard.sidebar.text_input[0].set_value("http-demo").run(timeout=10)
    assert not dashboard.exception
    assert kpi_values(dashboard)[:3] == ["3", "0", "0"]
    next(button for button in dashboard.button if button.label == "Ejecutar detección").click().run(timeout=10)
    assert not dashboard.exception
    assert kpi_values(dashboard)[:3] == ["3", "2", "1"]
    dashboard.sidebar.radio[0].set_value("Investigation Workspace").run(timeout=10)
    assert not dashboard.exception
    assert not dashboard.error
    assert any(box.label == "Incidente en investigación" for box in dashboard.selectbox)
    graph_labels = [item.value for item in dashboard.caption] + [item.proto.body for item in dashboard.get("html")]
    assert any("nodos" in text.casefold() and "relaciones" in text.casefold() for text in graph_labels)
    relation = next(box for box in dashboard.selectbox if box.label == "Relación a investigar")
    assert relation.options
    assert relation.options[0].startswith("R001")
    assert not any(event_id in label for event_id in id_by_source.values() for label in relation.options)
    # Select a relation and prove the evidence panel resolves one of its real events.
    relation.set_value(0).run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    selected_event = next(box for box in dashboard.selectbox if box.label == "Evento de evidencia").value
    assert selected_event in {event_id for edge in graph["edges"] for event_id in edge["evidence_event_ids"]}
    assert not dashboard.get("download_button")
    next(button for button in dashboard.button if button.label == "Cargar archivo original").click().run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    original_files = dashboard.session_state["raw_files"]
    assert original_files[("http://127.0.0.1:8000", "synthetic", "http-demo", selected_event)] == payload
    assert dashboard.get("download_button")

    next(button for button in dashboard.button if button.label == "Evaluar respuesta →").click().run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    assert dashboard.session_state["nav"] == "Response Center"
    assert next(box for box in dashboard.selectbox if box.label == "Seleccionar incidente para respuesta").value == incident_id
    initial_actions = len(client.get(f"/v1/incidents/{incident_id}", params=partition).json()["containment_actions"])
    next(box for box in dashboard.text_input if box.label == "Tipo de acción").set_value("isolate_host")
    next(box for box in dashboard.text_input if box.label == "Objetivo exacto").set_value("host-1")
    next(box for box in dashboard.multiselect if box.label == "Evidencia que justifica la simulación").set_value([selected_event])
    next(button for button in dashboard.button if button.label == "Registrar simulación").click().run(timeout=10)
    assert client.get(f"/v1/incidents/{incident_id}", params=partition).json()["containment_actions"] == persisted["containment_actions"]
    next(box for box in dashboard.checkbox if box.label.startswith("Confirmo")).set_value(True)
    next(button for button in dashboard.button if button.label == "Registrar simulación").click().run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    assert any("mode=simulation" in message.value for message in dashboard.success)
    after_simulation = client.get(f"/v1/incidents/{incident_id}", params=partition).json()
    assert len(after_simulation["containment_actions"]) == initial_actions + 1
    assert after_simulation["containment_actions"][-1]["status"] == "simulated"

    dashboard.sidebar.radio[0].set_value("Attack Replay").run(timeout=10)
    from datetime import datetime
    dashboard.sidebar.date_input[0].set_value(datetime(2026, 10, 15).date())
    dashboard.sidebar.time_input[0].set_value(datetime(2026, 10, 15, 8, 1, 30).time())
    dashboard.run(timeout=10)
    next(button for button in dashboard.button if button.label == "Ejecutar detección hasta el corte").click().run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    assert kpi_values(dashboard)[0] == "2"
    next(button for button in dashboard.button if button.label == "Investigar →").click().run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    assert not any(button.label == "Cargar archivo original" for button in dashboard.button)
    assert not dashboard.get("download_button")
    assert next(button for button in dashboard.button if button.label == "Evaluar respuesta →").disabled
    assert client.get(f"/v1/incidents/{incident_id}", params=partition).json() == after_simulation

    dashboard.sidebar.toggle[0].set_value(False)
    dashboard.sidebar.radio[0].set_value("Response Center")
    dashboard.run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    assert next(box for box in dashboard.selectbox if box.label == "Seleccionar incidente para respuesta").value == incident_id
    dashboard.sidebar.selectbox[0].set_value("official").run(timeout=10)
    assert not dashboard.exception and not dashboard.error
    assert dashboard.session_state["selected_incident"] is None
    assert not any(box.label == "Seleccionar incidente para respuesta" for box in dashboard.selectbox)


def test_http_rejects_invalid_input_and_cross_partition_reads(tmp_path):
    repository = DuckDBSocRepository(tmp_path / "events.duckdb")
    raw_store = LocalRawTelemetryStore(tmp_path / "raw")
    client = _Client(create_app(repository=repository, raw_store=raw_store))
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/v1/events").status_code == 422
    assert client.get("/v1/events/missing", params={"dataset_kind": "synthetic", "dataset_id": "x"}).status_code == 404
    assert client.post("/v1/ingestions", json={
        "dataset_kind": "synthetic", "dataset_id": "x", "format": "jsonl", "source": "test",
        "content_base64": "not base64", "field_mapping": {"source_timestamp": "t", "event_type": "e"},
    }).status_code == 422
    assert client.post("/v1/detections/run", json={
        "dataset_kind": "synthetic", "dataset_id": "x", "as_of": "2026-10-15T08:00:00",
    }).status_code == 422


def test_csv_numeric_transfer_fields_reach_exfiltration_rule(tmp_path):
    repository = DuckDBSocRepository(tmp_path / "events.duckdb")
    raw_store = LocalRawTelemetryStore(tmp_path / "raw")
    client = _Client(create_app(repository=repository, raw_store=raw_store))
    partition = {"dataset_kind": "synthetic", "dataset_id": "csv-demo"}
    csv_bytes = (
        "id,timestamp,type,user,host,direction,destination_scope,bytes\n"
        "one,2026-10-15T08:00:00Z,data_transfer,alice,h1,outbound,external,6291456\n"
        "two,2026-10-15T08:01:00Z,data_transfer,alice,h1,outbound,external,6291456\n"
    ).encode()
    uploaded = client.post("/v1/ingestions", json={
        **partition, "format": "csv", "source": "local-csv-test",
        "content_base64": base64.b64encode(csv_bytes).decode(),
        "field_mapping": {"source_event_id": "id", "source_timestamp": "timestamp", "event_type": "type"},
    })
    assert uploaded.status_code == 200, uploaded.text
    assert len(uploaded.json()["accepted_event_ids"]) == 2
    detected = client.post("/v1/detections/run", json=partition)
    assert detected.status_code == 200, detected.text
    alerts = client.get("/v1/alerts", params=partition).json()
    assert any(alert["rule_id"] == "possible_exfiltration_v1" for alert in alerts)
