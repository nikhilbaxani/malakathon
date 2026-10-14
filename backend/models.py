"""Provider-independent records exchanged by the SOC components."""

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


Identifier = Annotated[str, Field(min_length=1)]
EvidenceIds = Annotated[list[Identifier], Field(min_length=1)]
DatasetKind = Literal["synthetic", "official"]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("timestamp_utc", "detected_at", "created_at", "generated_at", "requested_at", "authorized_at", check_fields=False)
    @classmethod
    def normalize_utc(cls, value: datetime | None) -> datetime | None:
        return value.astimezone(timezone.utc) if value is not None else None


class Event(ContractModel):
    event_id: Identifier
    dataset_id: Identifier
    dataset_kind: DatasetKind
    source: Identifier
    source_event_id: str | None = None
    source_timestamp: Identifier
    source_record_number: int | None = Field(default=None, ge=1)
    timestamp_utc: AwareDatetime
    event_type: Identifier
    raw_ref: Identifier
    attributes: dict[str, JsonValue] = Field(default_factory=dict)


class IngestionIssue(ContractModel):
    record_number: int = Field(ge=1)
    raw_ref: Identifier
    reason: Identifier


class IngestionResult(ContractModel):
    batch_id: Identifier
    dataset_id: Identifier
    dataset_kind: DatasetKind
    accepted_event_ids: list[Identifier] = Field(default_factory=list)
    errors: list[IngestionIssue] = Field(default_factory=list)


class Alert(ContractModel):
    alert_id: Identifier
    dataset_id: Identifier
    dataset_kind: DatasetKind
    rule_id: Identifier
    title: Identifier
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    detected_at: AwareDatetime
    evidence_event_ids: EvidenceIds

    @field_validator("evidence_event_ids")
    @classmethod
    def unique_evidence(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_event_ids must be unique")
        return value


class Incident(ContractModel):
    incident_id: Identifier
    dataset_id: Identifier
    dataset_kind: DatasetKind
    title: Identifier
    status: Literal["open", "investigating", "contained", "closed"]
    created_at: AwareDatetime
    alert_ids: EvidenceIds
    evidence_event_ids: EvidenceIds

    @field_validator("alert_ids", "evidence_event_ids")
    @classmethod
    def unique_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("reference IDs must be unique")
        return value


class DetectionResult(ContractModel):
    alerts: list[Alert] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)


class TriageResult(ContractModel):
    triage_id: Identifier
    incident_id: Identifier
    engine: Literal["deterministic", "jev"]
    assessment: Literal["needs_review", "likely_true_positive", "likely_false_positive"]
    summary: Identifier
    rationale: Identifier
    generated_at: AwareDatetime
    evidence_event_ids: EvidenceIds

    @field_validator("evidence_event_ids")
    @classmethod
    def unique_evidence(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("evidence_event_ids must be unique")
        return value


class ContainmentAction(ContractModel):
    action_id: Identifier
    incident_id: Identifier
    action_type: Identifier
    target: Identifier
    mode: Literal["simulation", "live"]
    status: Literal["proposed", "simulated", "approved", "executed", "failed", "rejected"]
    requested_at: AwareDatetime
    evidence_event_ids: EvidenceIds
    approval_ref: str | None = None
    authorized_by: str | None = None
    authorized_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def check_authorization(self) -> "ContainmentAction":
        if self.mode == "live" and not all((self.approval_ref, self.authorized_by, self.authorized_at)):
            raise ValueError("live action requires approval_ref, authorized_by and authorized_at")
        if self.mode == "simulation" and self.status in {"approved", "executed"}:
            raise ValueError("simulation cannot have a live execution status")
        if len(self.evidence_event_ids) != len(set(self.evidence_event_ids)):
            raise ValueError("evidence_event_ids must be unique")
        return self
