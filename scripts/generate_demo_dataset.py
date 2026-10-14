"""Generate an invented 30-day SOC fixture and separate ground truth."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


DATASET_ID = "gsec-synthetic-30d-v1"
BASE = datetime(2026, 9, 15, tzinfo=timezone.utc)
ATTACK_START = datetime(2026, 10, 13, 17, tzinfo=timezone.utc)
BENIGN_HOURS = (1, 4, 7, 10, 13, 16)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def build_dataset() -> tuple[list[dict], dict]:
    """Return stable events and labels; neither describes an official feed."""
    events: list[dict] = []
    benign_ids: list[str] = []
    for day in range(30):
        for slot, hour in enumerate(BENIGN_HOURS):
            event_id = f"benign-{day:02d}-{slot}"
            event = {
                "id": event_id,
                "timestamp": iso(BASE + timedelta(days=day, hours=hour)),
                "user": f"analyst-{day % 5}",
                "host": f"workstation-{day % 5}",
            }
            if slot == 0:
                event.update(type="login", outcome="success")
            elif slot == 1:
                event.update(type="privilege_change", outcome="denied", old_role="user", new_role="admin")
            elif slot == 2:
                event.update(type="data_transfer", direction="outbound", destination_scope="external", bytes=1048576)
            elif slot == 3:
                event.update(type="audit_logging_disabled", outcome="failed")
            elif slot == 4:
                event.update(type="data_transfer", direction="outbound", destination_scope="internal", bytes=15728640)
            else:
                event.update(type="service_stopped", outcome="denied")
            events.append(event)
            benign_ids.append(event_id)

    attack = [
        ("attack-privilege", 0, {"type": "privilege_change", "outcome": "success", "old_role": "user", "new_role": "admin"}),
        ("attack-transfer-1", 3, {"type": "data_transfer", "direction": "outbound", "destination_scope": "external", "bytes": 6291456}),
        ("attack-transfer-2", 7, {"type": "data_transfer", "direction": "outbound", "destination_scope": "external", "bytes": 6291456}),
        ("attack-sabotage", 10, {"type": "backup_deleted", "outcome": "success"}),
    ]
    for event_id, minute, attributes in attack:
        events.append({
            "id": event_id,
            "timestamp": iso(ATTACK_START + timedelta(minutes=minute)),
            "user": "suspect-demo", "host": "attack-host", **attributes,
        })
    events.sort(key=lambda event: (event["timestamp"], event["id"]))

    truth = {
        "schema_version": 1,
        "dataset_kind": "synthetic",
        "dataset_id": DATASET_ID,
        "description": "Invented local fixture; not official GSEC telemetry or an attack claim.",
        "window_start_utc": iso(BASE),
        "window_end_utc": iso(BASE + timedelta(days=30)),
        "benign_source_event_ids": benign_ids,
        "expected_alerts": [
            {
                "case_id": "campaign-1-privilege",
                "rule_id": "privilege_escalation_v1",
                "evidence_source_event_ids": ["attack-privilege"],
                "attack_start_utc": iso(ATTACK_START),
                "first_detectable_at_utc": iso(ATTACK_START),
            },
            {
                "case_id": "campaign-1-exfiltration",
                "rule_id": "possible_exfiltration_v1",
                "evidence_source_event_ids": ["attack-transfer-1", "attack-transfer-2"],
                "attack_start_utc": iso(ATTACK_START),
                "first_detectable_at_utc": iso(ATTACK_START + timedelta(minutes=7)),
            },
            {
                "case_id": "campaign-1-sabotage",
                "rule_id": "possible_sabotage_v1",
                "evidence_source_event_ids": ["attack-sabotage"],
                "attack_start_utc": iso(ATTACK_START),
                "first_detectable_at_utc": iso(ATTACK_START + timedelta(minutes=10)),
            },
        ],
    }
    return events, truth


def write_dataset(directory: Path) -> tuple[Path, Path]:
    events, truth = build_dataset()
    directory.mkdir(parents=True, exist_ok=True)
    telemetry = directory / "synthetic_30d.jsonl"
    labels = directory / "ground_truth.json"
    telemetry.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in events), encoding="utf-8")
    labels.write_text(json.dumps(truth, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return telemetry, labels


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[1] / "demo")
    args = parser.parse_args()
    telemetry, labels = write_dataset(args.output_dir)
    print(f"{telemetry}\n{labels}")


if __name__ == "__main__":
    main()
