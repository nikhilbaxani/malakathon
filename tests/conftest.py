"""Read visible console KPI values independently of their Streamlit renderer."""

from html.parser import HTMLParser

import pytest


class _KpiValues(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = []
        self.reading_value = False

    def handle_starttag(self, tag, attrs):
        classes = dict(attrs).get("class", "").split()
        if tag == "div" and "soc-kpi-value" in classes:
            self.reading_value = True

    def handle_data(self, data):
        if self.reading_value and data.strip():
            self.values.append(data.strip().replace(",", ""))

    def handle_endtag(self, tag):
        if tag == "div":
            self.reading_value = False


@pytest.fixture
def kpi_values():
    def read(app):
        parser = _KpiValues()
        for element in app.get("html"):
            parser.feed(element.proto.body)
        return parser.values or [metric.value for metric in app.metric]

    return read
