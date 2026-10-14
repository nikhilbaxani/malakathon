"""Normalize local telemetry without assuming an official dataset schema."""

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Literal, Mapping

from pydantic import ValidationError

from backend.models import DatasetKind, Event, IngestionIssue, IngestionResult
from backend.ports import RawTelemetryStore, SocRepository


class CsvJsonlIngestor:
    """Store exact input first, then process records independently when possible.

    Only `source_timestamp`, `event_type`, and optional `source_event_id` are
    canonical fields. Every unconsumed input field becomes an event attribute.
    Naive timestamps are quarantined because no timezone rule is configured.
    """

    def __init__(self, repository: SocRepository, raw_store: RawTelemetryStore) -> None:
        self.repository = repository
        self.raw_store = raw_store

    def ingest(
        self,
        payload: bytes,
        *,
        format: Literal["csv", "jsonl"],
        dataset_kind: DatasetKind,
        dataset_id: str,
        source: str,
        field_mapping: Mapping[str, str],
    ) -> IngestionResult:
        if format not in ("csv", "jsonl"):
            raise ValueError("format must be csv or jsonl")
        if dataset_kind not in ("synthetic", "official") or not dataset_id or not source:
            raise ValueError("valid dataset partition and source are required")
        required = {"source_timestamp", "event_type"}
        permitted = required | {"source_event_id"}
        if not required.issubset(field_mapping) or set(field_mapping) - permitted:
            raise ValueError("field_mapping requires source_timestamp and event_type, and permits source_event_id")
        if any(not isinstance(value, str) or not value for value in field_mapping.values()):
            raise ValueError("mapped input field names must be nonempty strings")
        if len(set(field_mapping.values())) != len(field_mapping):
            raise ValueError("mapped input fields must be distinct")
        raw_ref = self.raw_store.put(
            payload,
            dataset_kind=dataset_kind,
            dataset_id=dataset_id,
            source=source,
            source_event_id=None,
        )
        batch_id = hashlib.sha256(
            json.dumps([dataset_kind, dataset_id, source, raw_ref, format, dict(field_mapping)], sort_keys=True).encode()
        ).hexdigest()
        result = IngestionResult(batch_id=batch_id, dataset_kind=dataset_kind, dataset_id=dataset_id)
        try:
            decoded = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            result.errors.append(IngestionIssue(record_number=1, raw_ref=raw_ref, reason="input is not UTF-8"))
            return result

        def process(number: int, record: object) -> None:
            try:
                if not isinstance(record, dict):
                    raise ValueError("record must be an object")
                absent = [name for name in field_mapping.values() if name not in record]
                if absent:
                    raise ValueError(f"mapped input fields absent: {', '.join(absent)}")
                event = self._normalize(
                    record, number=number, raw_ref=raw_ref, dataset_kind=dataset_kind,
                    dataset_id=dataset_id, source=source, field_mapping=field_mapping,
                )
                self.repository.put_events([event])
                if event.event_id not in result.accepted_event_ids:
                    result.accepted_event_ids.append(event.event_id)
            except (ValueError, ValidationError) as exc:
                result.errors.append(IngestionIssue(record_number=number, raw_ref=raw_ref, reason=str(exc)))

        if format == "jsonl":
            for number, line in enumerate(decoded.splitlines(), start=1):
                try:
                    process(number, json.loads(line))
                except json.JSONDecodeError as exc:
                    result.errors.append(IngestionIssue(record_number=number, raw_ref=raw_ref, reason=f"invalid JSON: {exc.msg}"))
        else:
            reader = csv.reader(io.StringIO(decoded, newline=""), strict=True)
            try:
                header = next(reader)
            except StopIteration:
                result.errors.append(IngestionIssue(record_number=1, raw_ref=raw_ref, reason="CSV header missing"))
                return result
            except csv.Error as exc:
                result.errors.append(IngestionIssue(record_number=1, raw_ref=raw_ref, reason=f"invalid CSV header: {exc}"))
                return result
            if len(header) != len(set(header)) or any(not name for name in header):
                result.errors.append(IngestionIssue(record_number=1, raw_ref=raw_ref, reason="CSV header has empty or duplicate columns"))
                return result
            number = 0
            try:
                for number, values in enumerate(reader, start=1):
                    if len(values) != len(header):
                        result.errors.append(IngestionIssue(record_number=number, raw_ref=raw_ref, reason="CSV column count differs from header"))
                    else:
                        process(number, dict(zip(header, values)))
            except csv.Error as exc:
                result.errors.append(IngestionIssue(record_number=number + 1, raw_ref=raw_ref, reason=f"invalid CSV: {exc}"))
        return result

    @staticmethod
    def _normalize(
        record: dict,
        *,
        number: int,
        raw_ref: str,
        dataset_kind: DatasetKind,
        dataset_id: str,
        source: str,
        field_mapping: Mapping[str, str],
    ) -> Event:
        literal_time = record[field_mapping["source_timestamp"]]
        event_type = record[field_mapping["event_type"]]
        source_event_id = record[field_mapping["source_event_id"]] if "source_event_id" in field_mapping else None
        if not isinstance(literal_time, str) or not literal_time:
            raise ValueError("source timestamp must be a nonempty string")
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event type must be a nonempty string")
        if source_event_id is not None and not isinstance(source_event_id, str):
            raise ValueError("source event ID must be a string")
        try:
            timestamp = datetime.fromisoformat(literal_time)
        except ValueError as exc:
            raise ValueError("source timestamp is not ISO 8601") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("source timestamp has no timezone")
        identity = [dataset_kind, dataset_id, source, source_event_id]
        if source_event_id is None:
            identity.extend([raw_ref, number])
        event_id = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode("utf-8")).hexdigest()
        consumed = set(field_mapping.values())
        return Event(
            event_id=event_id,
            dataset_kind=dataset_kind,
            dataset_id=dataset_id,
            source=source,
            source_event_id=source_event_id,
            source_timestamp=literal_time,
            source_record_number=number,
            timestamp_utc=timestamp.astimezone(timezone.utc),
            event_type=event_type,
            raw_ref=raw_ref,
            attributes={key: value for key, value in record.items() if key not in consumed},
        )
