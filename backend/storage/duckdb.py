"""DuckDB implementation of the SOC repository contract."""

from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Iterable, TypeVar

import duckdb
from pydantic import BaseModel

from backend.models import (
    Alert,
    ContainmentAction,
    DatasetKind,
    Event,
    Incident,
    TriageResult,
)

Record = TypeVar("Record", bound=BaseModel)


class DuckDBSocRepository:
    """Persist records by dataset partition; writes are idempotent, not mutable."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._db = duckdb.connect(self.db_path)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id VARCHAR PRIMARY KEY,
                dataset_kind VARCHAR NOT NULL,
                dataset_id VARCHAR NOT NULL,
                timestamp_utc TIMESTAMPTZ NOT NULL,
                payload VARCHAR NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id VARCHAR PRIMARY KEY,
                dataset_kind VARCHAR NOT NULL,
                dataset_id VARCHAR NOT NULL,
                payload VARCHAR NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id VARCHAR PRIMARY KEY,
                dataset_kind VARCHAR NOT NULL,
                dataset_id VARCHAR NOT NULL,
                payload VARCHAR NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS triage_results (
                triage_id VARCHAR PRIMARY KEY,
                incident_id VARCHAR NOT NULL,
                dataset_kind VARCHAR NOT NULL,
                dataset_id VARCHAR NOT NULL,
                payload VARCHAR NOT NULL
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS containment_actions (
                action_id VARCHAR PRIMARY KEY,
                incident_id VARCHAR NOT NULL,
                dataset_kind VARCHAR NOT NULL,
                dataset_id VARCHAR NOT NULL,
                payload VARCHAR NOT NULL
            )
        """)
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS event_time_idx ON events(dataset_kind, dataset_id, timestamp_utc, event_id)"
        )
        for table in ("alerts", "incidents"):
            self._db.execute(
                f"CREATE INDEX IF NOT EXISTS {table}_partition_idx ON {table}(dataset_kind, dataset_id)"
            )
        for table in ("triage_results", "containment_actions"):
            self._db.execute(
                f"CREATE INDEX IF NOT EXISTS {table}_incident_idx ON {table}(dataset_kind, dataset_id, incident_id)"
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _partition(self, table: str, id_column: str, record_id: str) -> tuple[str, str] | None:
        row = self._db.execute(
            f"SELECT dataset_kind, dataset_id FROM {table} WHERE {id_column} = ?", [record_id]
        ).fetchone()
        return (row[0], row[1]) if row else None

    def _check_refs(self, table: str, id_column: str, ids: Iterable[str], partition: tuple[str, str]) -> None:
        for record_id in ids:
            if self._partition(table, id_column, record_id) != partition:
                raise ValueError(f"{table} reference missing or outside dataset partition: {record_id}")

    def _insert(self, table: str, id_column: str, record_id: str, record: BaseModel, extra: tuple = ()) -> None:
        payload = record.model_dump_json()
        existing = self._db.execute(
            f"SELECT payload FROM {table} WHERE {id_column} = ?", [record_id]
        ).fetchone()
        if existing:
            if table == "events":
                first = Event.model_validate_json(existing[0]).model_dump(exclude={"raw_ref", "source_record_number"})
                repeated = Event.model_validate_json(payload).model_dump(exclude={"raw_ref", "source_record_number"})
                equivalent = first == repeated
            elif table == "alerts":
                first = Alert.model_validate_json(existing[0]).model_dump(exclude={"detected_at"})
                repeated = Alert.model_validate_json(payload).model_dump(exclude={"detected_at"})
                equivalent = first == repeated
            elif table == "incidents":
                first = Incident.model_validate_json(existing[0]).model_dump(exclude={"created_at"})
                repeated = Incident.model_validate_json(payload).model_dump(exclude={"created_at"})
                equivalent = first == repeated
            else:
                equivalent = existing[0] == payload
            if not equivalent:
                raise ValueError(f"conflicting {table} ID: {record_id}")
            return
        columns = [id_column, "dataset_kind", "dataset_id"]
        values: list = [record_id, record.dataset_kind, record.dataset_id]  # type: ignore[attr-defined]
        if table == "events":
            columns.append("timestamp_utc")
            values.append(record.timestamp_utc)  # type: ignore[attr-defined]
        if extra:
            columns.append("incident_id")
            values.extend(extra)
        columns.append("payload")
        values.append(payload)
        placeholders = ", ".join("?" for _ in values)
        self._db.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})", values
        )

    def _transaction(self, callback) -> None:
        with self._lock:
            self._db.execute("BEGIN TRANSACTION")
            try:
                callback()
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def put_events(self, events: list[Event]) -> None:
        self._transaction(lambda: [self._insert("events", "event_id", item.event_id, item) for item in events])

    def list_events(
        self,
        *,
        dataset_kind: DatasetKind,
        dataset_id: str,
        from_utc: datetime | None = None,
        to_utc: datetime | None = None,
        as_of: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Event]:
        if limit < 0 or offset < 0:
            raise ValueError("limit and offset must be nonnegative")
        for value in (from_utc, to_utc, as_of):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError("time filters must have a timezone")
        sql = "SELECT payload FROM events WHERE dataset_kind = ? AND dataset_id = ?"
        parameters: list = [dataset_kind, dataset_id]
        for clause, value in (("timestamp_utc >= ?", from_utc), ("timestamp_utc <= ?", to_utc), ("timestamp_utc <= ?", as_of)):
            if value is not None:
                sql += f" AND {clause}"
                parameters.append(value)
        sql += " ORDER BY timestamp_utc, event_id LIMIT ? OFFSET ?"
        parameters.extend([limit, offset])
        with self._lock:
            rows = self._db.execute(sql, parameters).fetchall()
        return [Event.model_validate_json(row[0]) for row in rows]

    def get_event(self, event_id: str, *, dataset_kind: DatasetKind, dataset_id: str) -> Event | None:
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM events WHERE event_id = ? AND dataset_kind = ? AND dataset_id = ?",
                [event_id, dataset_kind, dataset_id],
            ).fetchone()
        return Event.model_validate_json(row[0]) if row else None

    def put_alerts(self, alerts: list[Alert]) -> None:
        def write() -> None:
            for item in alerts:
                self._check_refs("events", "event_id", item.evidence_event_ids, (item.dataset_kind, item.dataset_id))
                self._insert("alerts", "alert_id", item.alert_id, item)
        self._transaction(write)

    def list_alerts(self, *, dataset_kind: DatasetKind, dataset_id: str) -> list[Alert]:
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM alerts WHERE dataset_kind = ? AND dataset_id = ? ORDER BY alert_id",
                [dataset_kind, dataset_id],
            ).fetchall()
        return [Alert.model_validate_json(row[0]) for row in rows]

    def put_incidents(self, incidents: list[Incident]) -> None:
        def write() -> None:
            for item in incidents:
                partition = (item.dataset_kind, item.dataset_id)
                self._check_refs("alerts", "alert_id", item.alert_ids, partition)
                self._check_refs("events", "event_id", item.evidence_event_ids, partition)
                self._insert("incidents", "incident_id", item.incident_id, item)
        self._transaction(write)

    def list_incidents(self, *, dataset_kind: DatasetKind, dataset_id: str) -> list[Incident]:
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM incidents WHERE dataset_kind = ? AND dataset_id = ? ORDER BY incident_id",
                [dataset_kind, dataset_id],
            ).fetchall()
        return [Incident.model_validate_json(row[0]) for row in rows]

    def get_incident(self, incident_id: str, *, dataset_kind: DatasetKind, dataset_id: str) -> Incident | None:
        with self._lock:
            row = self._db.execute(
                "SELECT payload FROM incidents WHERE incident_id = ? AND dataset_kind = ? AND dataset_id = ?",
                [incident_id, dataset_kind, dataset_id],
            ).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def put_triage_result(self, result: TriageResult) -> None:
        def write() -> None:
            partition = self._partition("incidents", "incident_id", result.incident_id)
            if partition is None:
                raise ValueError("incident does not exist")
            self._check_refs("events", "event_id", result.evidence_event_ids, partition)
            self._insert("triage_results", "triage_id", result.triage_id, _Partitioned(result, *partition), (result.incident_id,))
        self._transaction(write)

    def list_triage_results(self, incident_id: str, *, dataset_kind: DatasetKind, dataset_id: str) -> list[TriageResult]:
        return self._list_children("triage_results", TriageResult, incident_id, dataset_kind, dataset_id)

    def put_containment_action(self, action: ContainmentAction) -> None:
        if action.mode != "simulation":
            raise ValueError("local repository only records containment simulations")
        def write() -> None:
            partition = self._partition("incidents", "incident_id", action.incident_id)
            if partition is None:
                raise ValueError("incident does not exist")
            self._check_refs("events", "event_id", action.evidence_event_ids, partition)
            self._insert("containment_actions", "action_id", action.action_id, _Partitioned(action, *partition), (action.incident_id,))
        self._transaction(write)

    def list_containment_actions(self, incident_id: str, *, dataset_kind: DatasetKind, dataset_id: str) -> list[ContainmentAction]:
        return self._list_children("containment_actions", ContainmentAction, incident_id, dataset_kind, dataset_id)

    def _list_children(self, table: str, model: type[Record], incident_id: str, dataset_kind: DatasetKind, dataset_id: str) -> list[Record]:
        with self._lock:
            rows = self._db.execute(
                f"SELECT payload FROM {table} WHERE incident_id = ? AND dataset_kind = ? AND dataset_id = ? ORDER BY {('triage_id' if table == 'triage_results' else 'action_id')}",
                [incident_id, dataset_kind, dataset_id],
            ).fetchall()
        return [model.model_validate_json(row[0]) for row in rows]


class _Partitioned:
    """Adds an incident's verified partition while retaining child JSON shape."""

    def __init__(self, record: BaseModel, dataset_kind: str, dataset_id: str) -> None:
        self.record = record
        self.dataset_kind = dataset_kind
        self.dataset_id = dataset_id

    def model_dump_json(self) -> str:
        return self.record.model_dump_json()
