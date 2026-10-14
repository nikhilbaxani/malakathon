"""Security and contract checks for the offline attack graph UI."""

import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from frontend.api import SocApi
from frontend.graph import MAX_NODES, graph_view, missing_optional_types, render_graph_html


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({"nodes": [], "edges": [], "metadata": {}}).encode()


def test_graph_request_uses_partition_cutoff_and_120_node_limit(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return FakeResponse()

    monkeypatch.setattr("frontend.api.urlopen", fake_urlopen)
    cutoff = datetime(2026, 10, 14, 10, tzinfo=timezone.utc)
    SocApi("http://localhost:8000").incident_graph("incident/1", "synthetic", "demo", as_of=cutoff, max_nodes=500)
    url = urlparse(requests[0].full_url)
    assert url.path.endswith("/incident%2F1/graph")
    assert parse_qs(url.query) == {
        "dataset_kind": ["synthetic"], "dataset_id": ["demo"],
        "as_of": [cutoff.isoformat()], "max_nodes": [str(MAX_NODES)],
    }


def test_graph_html_keeps_untrusted_text_in_data_not_markup():
    attack = '<script>alert(1)</script></script><img src=x onerror="alert(1)">'
    node = {"id": "n1", "type": "event", "label": attack, "attributes": {"payload": attack}}
    edge = {"source": "n1", "target": "n1", "type": attack, "evidence_event_ids": [attack]}
    html = render_graph_html([node], [edge])
    assert attack not in html
    assert "atob(encoded)" in html
    assert "textContent" in html
    assert "https://" not in html
    assert "cdn" not in html.lower()


def test_graph_view_handles_missing_optional_entities_and_bounds_output():
    nodes = [{"id": f"event-{number}", "type": "event", "label": str(number), "attributes": {}}
             for number in range(MAX_NODES + 5)]
    graph = {"nodes": nodes, "edges": [
        {"source": "event-0", "target": "event-1", "evidence_event_ids": ["e1"],
         "time_start_utc": "2026-10-14T09:00:00Z"},
        {"source": "event-1", "target": "event-2", "evidence_event_ids": ["e2"],
         "time_start_utc": "2026-10-14T11:00:00Z"},
    ]}
    cutoff = datetime(2026, 10, 14, 10, tzinfo=timezone.utc)
    visible_nodes, visible_edges, truncated = graph_view(
        graph, selected_types={"event"}, visible_event_ids={"e1"}, as_of=cutoff,
    )
    assert len(visible_nodes) == MAX_NODES
    assert len(visible_edges) == 1
    assert visible_edges[0]["evidence_event_ids"] == ["e1"]
    assert truncated


def test_empty_graph_can_be_rendered_without_optional_entities():
    assert graph_view({"nodes": [], "edges": []}) == ([], [], False)
    assert "Grafo de ataque interactivo" in render_graph_html([], [])


def test_type_filter_removes_edges_to_hidden_nodes():
    graph = {
        "nodes": [
            {"id": "event-1", "type": "event", "label": "Evento"},
            {"id": "host-1", "type": "host", "label": "Host"},
        ],
        "edges": [{"source": "event-1", "target": "host-1", "evidence_event_ids": ["e1"]}],
    }
    nodes, edges, truncated = graph_view(graph, selected_types={"event"})
    assert [node["id"] for node in nodes] == ["event-1"]
    assert edges == []
    assert not truncated


def test_optional_entity_presence_is_case_insensitive():
    assert missing_optional_types(["event", "ip", "file", "process"]) == []
    assert missing_optional_types(["IP", "host"]) == ["FILE", "PROCESS"]
