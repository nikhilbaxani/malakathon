"""Regression checks for checked-in truth and a serverless full demo run."""

import asyncio
import io
from pathlib import Path
from urllib.parse import urlparse

import httpx

from backend.api.app import create_app
from backend.storage import DuckDBSocRepository, LocalRawTelemetryStore
from scripts import load_demo as loader
from scripts.evaluate_demo import evaluate
from scripts.generate_demo_dataset import write_dataset


ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "demo" / "synthetic_30d.jsonl"
TRUTH = ROOT / "demo" / "ground_truth.json"


def test_demo_fixture_is_reproducible_and_truth_is_measurable(tmp_path):
    generated_telemetry, generated_truth = write_dataset(tmp_path)
    assert generated_telemetry.read_bytes() == TELEMETRY.read_bytes()
    assert generated_truth.read_bytes() == TRUTH.read_bytes()
    metrics = evaluate(TELEMETRY, TRUTH)
    assert (metrics["event_count"], metrics["benign_event_count"]) == (184, 180)
    assert (metrics["true_positive"], metrics["false_positive"], metrics["false_negative"]) == (3, 0, 0)
    assert [case["time_to_detect_event_seconds"] for case in metrics["cases"]] == [0, 420, 600]
    assert all(case["matches_truth_cutoff"] for case in metrics["cases"])


def test_demo_loader_full_flow_without_external_server(tmp_path, monkeypatch):
    repository = DuckDBSocRepository(tmp_path / "events.duckdb")
    raw_store = LocalRawTelemetryStore(tmp_path / "raw")
    app = create_app(repository=repository, raw_store=raw_store)

    def call_asgi(method, url, data=None):
        async def run():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
                return await client.request(method, url, content=data, headers={"content-type": "application/json"})

        return asyncio.run(run())

    def asgi_urlopen(request, timeout):
        parsed = urlparse(request.full_url)
        response = call_asgi(request.get_method(), parsed.path + (f"?{parsed.query}" if parsed.query else ""), request.data)
        assert response.status_code == 200, response.text
        return io.BytesIO(response.content)

    monkeypatch.setattr(loader, "urlopen", asgi_urlopen)
    summary = loader.load_demo(
        "http://127.0.0.1:8000", TELEMETRY, TRUTH,
        with_triage=True, with_simulation=True,
    )
    assert summary == {
        "dataset_kind": "synthetic", "dataset_id": "gsec-synthetic-30d-v1",
        "accepted_events": 184, "alerts": 3, "incidents": 1,
        "triage_engine": "deterministic", "containment_mode": "simulation",
    }
    partition = {"dataset_kind": "synthetic", "dataset_id": "gsec-synthetic-30d-v1"}
    incident = repository.list_incidents(**partition)[0]
    before = call_asgi("GET", f"/v1/incidents/{incident.incident_id}?dataset_kind=synthetic&dataset_id=gsec-synthetic-30d-v1").json()
    assert len(before["events"]) == 4
    assert len(before["triage_results"]) == 1
    assert len(before["containment_actions"]) == 1
    repeated = loader.load_demo(
        "http://127.0.0.1:8000", TELEMETRY, TRUTH,
        with_triage=True, with_simulation=True,
    )
    assert repeated == summary
    unchanged = call_asgi("GET", f"/v1/incidents/{incident.incident_id}?dataset_kind=synthetic&dataset_id=gsec-synthetic-30d-v1").json()
    assert unchanged == before

    replay = call_asgi(
        "POST", "/v1/detections/run",
        b'{"dataset_kind":"synthetic","dataset_id":"gsec-synthetic-30d-v1","as_of":"2026-10-13T17:05:00Z"}',
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["persisted"] is False
    assert len(replay.json()["alerts"]) == 1
    assert len(replay.json()["incidents"]) == 1
    after = call_asgi("GET", f"/v1/incidents/{incident.incident_id}?dataset_kind=synthetic&dataset_id=gsec-synthetic-30d-v1").json()
    assert after == before
    assert len(repository.list_alerts(**partition)) == 3
    assert len(repository.list_incidents(**partition)) == 1


def test_demo_loader_refuses_non_loopback_endpoint():
    for address in ("https://127.0.0.1:8000", "http://0.0.0.0:8000", "http://example.com:8000"):
        try:
            loader.local_api_url(address)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted non-loopback URL: {address}")
