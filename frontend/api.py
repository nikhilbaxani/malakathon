"""Small HTTP client for the shared /v1 contract."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


class ApiError(RuntimeError):
    """The API could not complete a console request."""


class SocApi:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None
    ) -> Any:
        query = urlencode({key: value for key, value in (params or {}).items() if value is not None})
        url = f"{self.base_url}{path}" + (f"?{query}" if query else "")
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        request = Request(url, data=payload, method=method, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.load(response)
        except HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8"))
            except (UnicodeError, ValueError):
                detail = exc.reason
            raise ApiError(f"HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, ValueError) as exc:
            raise ApiError(str(exc)) from exc

    @staticmethod
    def _partition(kind: str, dataset_id: str) -> dict[str, str]:
        return {"dataset_kind": kind, "dataset_id": dataset_id}

    def health(self) -> Any:
        return self._request("GET", "/health")

    def events(
        self, kind: str, dataset_id: str, *, as_of: datetime | None = None, limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        params = {**self._partition(kind, dataset_id), "limit": limit, "offset": offset}
        if as_of is not None:
            params["as_of"] = as_of.isoformat()
        return self._request("GET", "/v1/events", params=params)

    def all_events(
        self, kind: str, dataset_id: str, *, as_of: datetime | None = None, page_size: int = 200
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while True:
            page = self.events(kind, dataset_id, as_of=as_of, limit=page_size, offset=len(events))
            if not isinstance(page, list):
                raise ApiError("GET /v1/events debe devolver una lista JSON")
            events.extend(page)
            if len(page) < page_size:
                return events

    def alerts(self, kind: str, dataset_id: str) -> list[dict[str, Any]]:
        return self._request("GET", "/v1/alerts", params=self._partition(kind, dataset_id))

    def incidents(self, kind: str, dataset_id: str) -> list[dict[str, Any]]:
        return self._request("GET", "/v1/incidents", params=self._partition(kind, dataset_id))

    def raw_event(self, event_id: str, kind: str, dataset_id: str) -> bytes:
        """Fetch the exact source file, which may contain several event records."""
        path = f"/v1/events/{quote(event_id, safe='')}/raw"
        query = urlencode(self._partition(kind, dataset_id))
        request = Request(f"{self.base_url}{path}?{query}", method="GET")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except HTTPError as exc:
            raise ApiError(f"HTTP {exc.code}: no se pudo recuperar el archivo original") from exc
        except (URLError, TimeoutError, ValueError) as exc:
            raise ApiError(str(exc)) from exc

    def incident_detail(self, incident_id: str, kind: str, dataset_id: str) -> dict[str, Any]:
        path = f"/v1/incidents/{quote(incident_id, safe='')}"
        return self._request("GET", path, params=self._partition(kind, dataset_id))

    def incident_graph(
        self, incident_id: str, kind: str, dataset_id: str, *, as_of: datetime | None = None,
        max_nodes: int = 120,
    ) -> dict[str, Any]:
        path = f"/v1/incidents/{quote(incident_id, safe='')}/graph"
        params: dict[str, Any] = {**self._partition(kind, dataset_id), "max_nodes": min(max_nodes, 120)}
        if as_of is not None:
            params["as_of"] = as_of.isoformat()
        return self._request("GET", path, params=params)

    def run_detection(self, kind: str, dataset_id: str, *, as_of: datetime | None = None) -> dict[str, Any]:
        body: dict[str, Any] = self._partition(kind, dataset_id)
        if as_of is not None:
            body["as_of"] = as_of.isoformat()
        return self._request("POST", "/v1/detections/run", body=body)

    def triage(self, incident_id: str, kind: str, dataset_id: str) -> dict[str, Any]:
        path = f"/v1/incidents/{quote(incident_id, safe='')}/triage"
        return self._request("POST", path, params=self._partition(kind, dataset_id))

    def simulate(
        self, incident_id: str, kind: str, dataset_id: str, action_type: str, target: str,
        evidence_event_ids: list[str],
    ) -> dict[str, Any]:
        path = f"/v1/incidents/{quote(incident_id, safe='')}/containment/simulate"
        return self._request(
            "POST", path, params=self._partition(kind, dataset_id),
            body={"action_type": action_type, "target": target, "evidence_event_ids": evidence_event_ids},
        )
