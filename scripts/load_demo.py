"""Load the labeled synthetic fixture into a loopback SOC API."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
MAPPING = {"source_timestamp": "timestamp", "event_type": "type", "source_event_id": "id"}


def local_api_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("the demo API must be a plain http://127.0.0.1:<port> URL")
    if parsed.port is None:
        raise ValueError("the demo API URL must specify a port")
    return f"http://127.0.0.1:{parsed.port}"


def request_json(url: str, *, body: dict | None = None, timeout: float = 20.0) -> dict | list:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(url, data=data, method="POST" if body is not None else "GET", headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"API HTTP {error.code}: {error.read().decode('utf-8', errors='replace')}") from error
    except URLError as error:
        raise RuntimeError(f"API unavailable at {url}: {error.reason}") from error


def load_demo(
    api_url: str,
    telemetry_path: Path,
    truth_path: Path,
    *,
    with_triage: bool = False,
    with_simulation: bool = False,
) -> dict:
    base = local_api_url(api_url)
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    if truth.get("dataset_kind") != "synthetic":
        raise ValueError("demo ground truth must be explicitly synthetic")
    payload = telemetry_path.read_bytes()
    request_json(f"{base}/health")
    partition = {"dataset_kind": "synthetic", "dataset_id": truth["dataset_id"]}
    ingestion = request_json(f"{base}/v1/ingestions", body={
        **partition,
        "format": "jsonl",
        "source": "gsec-synthetic-30d-fixture",
        "content_base64": base64.b64encode(payload).decode("ascii"),
        "field_mapping": MAPPING,
    })
    if ingestion["errors"]:
        raise RuntimeError(f"demo ingestion quarantined {len(ingestion['errors'])} records: {ingestion['errors'][:3]}")
    detection = request_json(f"{base}/v1/detections/run", body=partition)
    if detection.get("persisted") is not True:
        raise RuntimeError("full demo detection was not persisted")
    summary = {
        **partition,
        "accepted_events": len(ingestion["accepted_event_ids"]),
        "alerts": len(detection["alert_ids"]),
        "incidents": len(detection["incident_ids"]),
        "triage_engine": None,
        "containment_mode": None,
    }
    if with_triage or with_simulation:
        if len(detection["incident_ids"]) != 1:
            raise RuntimeError("the labeled fixture must produce exactly one incident for optional actions")
        incident_id = detection["incident_ids"][0]
        query = urlencode(partition)
        detail_url = f"{base}/v1/incidents/{incident_id}?{query}"
        detail = request_json(detail_url)
        if with_triage:
            existing_triage = detail.get("triage_results", [])
            triage = existing_triage[-1] if existing_triage else request_json(
                f"{base}/v1/incidents/{incident_id}/triage?{query}", body={}
            )
            summary["triage_engine"] = triage["engine"]
        if with_simulation:
            evidence_ids = detail["incident"]["evidence_event_ids"]
            prior_actions = [
                action for action in detail.get("containment_actions", [])
                if action.get("mode") == "simulation"
                and action.get("action_type") == "isolate_host"
                and action.get("target") == "attack-host"
                and set(action.get("evidence_event_ids", [])) == set(evidence_ids)
            ]
            action = prior_actions[0] if prior_actions else request_json(
                f"{base}/v1/incidents/{incident_id}/containment/simulate?{query}",
                body={"action_type": "isolate_host", "target": "attack-host", "evidence_event_ids": evidence_ids},
            )
            if action["mode"] != "simulation" or action["status"] != "simulated":
                raise RuntimeError("API returned an unexpected containment mode or status")
            summary["containment_mode"] = action["mode"]
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--telemetry", type=Path, default=ROOT / "demo" / "synthetic_30d.jsonl")
    parser.add_argument("--truth", type=Path, default=ROOT / "demo" / "ground_truth.json")
    parser.add_argument("--with-triage", action="store_true")
    parser.add_argument("--with-simulation", action="store_true")
    args = parser.parse_args()
    summary = load_demo(
        args.api_url, args.telemetry, args.truth,
        with_triage=args.with_triage, with_simulation=args.with_simulation,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
