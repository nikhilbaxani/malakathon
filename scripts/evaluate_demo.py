"""Measure rule-level matches and event-time detection delay on the local fixture."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from backend.detection import RuleBasedDetectionEngine
from backend.ingestion import CsvJsonlIngestor
from backend.storage import DuckDBSocRepository, LocalRawTelemetryStore


ROOT = Path(__file__).resolve().parents[1]
MAPPING = {"source_timestamp": "timestamp", "event_type": "type", "source_event_id": "id"}


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("ground truth timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def evaluate(telemetry_path: Path, truth_path: Path) -> dict:
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    if truth.get("dataset_kind") != "synthetic":
        raise ValueError("only explicitly synthetic ground truth is supported")
    source_rows = [json.loads(line) for line in telemetry_path.read_text(encoding="utf-8").splitlines()]
    source_ids = [row["id"] for row in source_rows]
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("fixture source event IDs must be unique")
    expected = truth["expected_alerts"]
    expected_keys = Counter(
        (item["rule_id"], frozenset(item["evidence_source_event_ids"])) for item in expected
    )
    benign_ids = set(truth["benign_source_event_ids"])
    attack_ids = {event_id for item in expected for event_id in item["evidence_source_event_ids"]}
    if benign_ids & attack_ids or benign_ids | attack_ids != set(source_ids):
        raise ValueError("ground truth must label every source event exactly once")

    with TemporaryDirectory(prefix="gsec-evaluate-") as temporary:
        root = Path(temporary)
        repository = DuckDBSocRepository(root / "events.duckdb")
        ingestor = CsvJsonlIngestor(repository, LocalRawTelemetryStore(root / "raw"))
        result = ingestor.ingest(
            telemetry_path.read_bytes(), format="jsonl", dataset_kind="synthetic",
            dataset_id=truth["dataset_id"], source="ground-truth-fixture", field_mapping=MAPPING,
        )
        if result.errors or len(result.accepted_event_ids) != len(source_rows):
            raise ValueError(f"fixture ingestion failed: {result.errors}")
        events = repository.list_events(
            dataset_kind="synthetic", dataset_id=truth["dataset_id"], limit=len(source_rows) + 1
        )
        by_internal_id = {event.event_id: event.source_event_id for event in events}
        detector = RuleBasedDetectionEngine()
        at = parse_time(truth["window_end_utc"])

        def key_for(alert) -> tuple[str, frozenset[str]]:
            return alert.rule_id, frozenset(by_internal_id[event_id] for event_id in alert.evidence_event_ids)

        full = detector.detect(events, detected_at=at)
        actual_keys = Counter(key_for(alert) for alert in full.alerts)
        true_positive = sum((actual_keys & expected_keys).values())
        false_positive = sum((actual_keys - expected_keys).values())
        false_negative = sum((expected_keys - actual_keys).values())
        event_times = sorted({event.timestamp_utc for event in events})
        cases: list[dict] = []
        for item in expected:
            expected_key = item["rule_id"], frozenset(item["evidence_source_event_ids"])
            attack_start = parse_time(item["attack_start_utc"])
            first_seen = None
            for cutoff in event_times:
                if cutoff < attack_start:
                    continue
                selected = [event for event in events if event.timestamp_utc <= cutoff]
                snapshot = detector.detect(selected, detected_at=at)
                if any(key_for(alert) == expected_key for alert in snapshot.alerts):
                    first_seen = cutoff
                    break
            cases.append({
                "case_id": item["case_id"],
                "first_detected_event_time_utc": first_seen.isoformat().replace("+00:00", "Z") if first_seen else None,
                "time_to_detect_event_seconds": int((first_seen - attack_start).total_seconds()) if first_seen else None,
                "matches_truth_cutoff": first_seen == parse_time(item["first_detectable_at_utc"]),
            })
        repository.close()
    return {
        "dataset_kind": "synthetic",
        "dataset_id": truth["dataset_id"],
        "event_count": len(source_rows),
        "benign_event_count": len(benign_ids),
        "alert_count": sum(actual_keys.values()),
        "incident_count": len(full.incidents),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": true_positive / (true_positive + false_positive) if true_positive + false_positive else None,
        "recall": true_positive / (true_positive + false_negative) if true_positive + false_negative else None,
        "cases": cases,
        "metric_note": "Detection delay is measured in event time by replaying each cutoff; it is not live processing latency.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telemetry", type=Path, default=ROOT / "demo" / "synthetic_30d.jsonl")
    parser.add_argument("--truth", type=Path, default=ROOT / "demo" / "ground_truth.json")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.telemetry, args.truth), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
