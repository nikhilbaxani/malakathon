# GSEC Sentinel — Project Instructions

## Context
University cybersecurity hackathon, 15-16 October 2026.

Scenario:
Emergency SOC at Google Safety Engineering Center.
Analyze 30 days of synthetic telemetry, reconstruct
a suspected intrusion involving zero-day exfiltration
and sabotage, and support live containment.

Team: 4 students.
Development window: approximately 8-12 hours.

## Architecture
Python 3.11+
FastAPI
DuckDB
Streamlit
Pytest
TypeSafe Jev (optional)
OCI (optional, requirements unconfirmed)

## Priorities
P0: Telemetry ingestion and data storage.
P0: Threat detection with traceable evidence.
P0: Functional web console.
P1: Attack reconstruction and timeline.
P1: Jev-assisted triage.
P1: Authorized containment or labeled simulation.
P2: Time-travel replay and attack graph.
P2: OCI integration if required.

## Engineering rules
- Read CONTRACTS.md before implementation.
- Do not invent official dataset formats.
- Keep original telemetry and normalized events.
- Preserve event IDs and source timestamps.
- Normalize timestamps to UTC.
- Keep synthetic and official data separate.
- All detections must reference evidence IDs.
- Do not invent AI outputs or Jev API endpoints.
- Provide a deterministic fallback without Jev.
- Do not execute real containment without approval.
- Never commit credentials or secrets.
- Add automated tests for core functionality.
- Do not overwrite existing repository files blindly.
- Keep OCI integration optional and modular.

## Multiagent coordination
- Coordinator owns shared contracts and integration.
- soc_data owns ingestion and storage.
- soc_hunter owns detection.
- soc_ai owns AI integration.
- soc_ui owns frontend.
- soc_reviewer audits without editing.
- Agents must not edit files owned by another agent.
- Do not run concurrent Git operations.
- Report changed files, tests and unresolved issues.

## Success condition
A reproducible end-to-end SOC demo:
telemetry -> detection -> incident -> triage
-> dashboard -> authorized response/simulation.
