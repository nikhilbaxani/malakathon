"""Security checks for the new HTML presentation of API data."""

from datetime import datetime, timezone
from html import escape
from html.parser import HTMLParser

from frontend import visual


def test_console_html_keeps_api_text_inert(monkeypatch):
    rendered = []
    monkeypatch.setattr(visual.st, "html", rendered.append)
    attack = '<img src=x onerror="alert(1)"><script>attack()</script>&'
    event = {
        "event_id": "e1", "timestamp_utc": "2026-10-15T08:00:00Z",
        "event_type": attack, "source": attack, "attributes": {"host": attack},
    }
    visual.topbar(attack, attack, "synthetic", loaded_at=datetime.now(timezone.utc))
    visual.panel_heading(attack, attack)
    visual.alert_summary({"title": attack, "rule_id": attack, "severity": "high", "evidence_event_ids": ["e1"]})
    visual.activity_feed([event])
    visual.evidence_header(event)
    visual.status_strip(attack, 1, 1)
    visual.attributes_summary({attack: attack})
    assert len(rendered) == 7
    for html in rendered:
        assert attack not in html
        assert "<script>attack()" not in html
        assert escape(attack, quote=True) in html


def test_badge_variant_cannot_inject_markup():
    attack = '\"><img src=x onerror=alert(1)>'
    html = visual.badge(attack, attack)
    assert '<img' not in html
    assert 'soc-badge-neutral' in html
    assert escape(attack, quote=True) in html


class _Numbers(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {"soc-kpi-value": [], "soc-summary-number": []}
        self.reading = None

    def handle_starttag(self, _tag, attrs):
        for name in dict(attrs).get("class", "").split():
            if name in self.values:
                self.reading = name

    def handle_data(self, data):
        if self.reading and data.strip():
            self.values[self.reading].append(int(data.strip().replace(",", "")))

    def handle_endtag(self, _tag):
        self.reading = None


def test_panels_count_real_data_without_inventing_entities(monkeypatch):
    rendered = []
    monkeypatch.setattr(visual.st, "html", rendered.append)
    events = [
        {"event_id": "e1", "attributes": {"user": "alice", "host": "h1"}},
        {"event_id": "e2", "attributes": {"user": "alice", "host": "h1", "destination_ip": "192.0.2.4"}},
        {"event_id": "e3", "attributes": {"user": "bob", "host": "h2", "file_path": "/fixture"}},
        {"event_id": "e4", "attributes": {}},
    ]
    alerts = [{"severity": level} for level in ("critical", "high", "medium")]
    visual.kpis(events, alerts, [{"incident_id": "i1"}])
    visual.entities_summary(events)
    parser = _Numbers()
    for html in rendered:
        parser.feed(html)
    assert parser.values["soc-kpi-value"] == [4, 3, 1, 2]
    assert parser.values["soc-summary-number"] == [2, 2, 1, 1]
    assert "no demuestra compromiso" in rendered[1]

    rendered.clear()
    visual.kpis([], [], [])
    visual.entities_summary([{"event_id": "without-entities", "attributes": {}}])
    parser = _Numbers()
    for html in rendered:
        parser.feed(html)
    assert parser.values["soc-kpi-value"] == [0, 0, 0, 0]
    assert parser.values["soc-summary-number"] == [0, 0, 0, 0]
