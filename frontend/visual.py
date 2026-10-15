"""Escaped, inert presentation components for the SOC workstation."""
from __future__ import annotations

import base64
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

import streamlit as st

from frontend.presentation import entity_rows, severity_label
from frontend.replay import parse_utc


ICONS = {
    "events": '<path d="M4 4h16v16H4zM8 8h8M8 12h8M8 16h5"/>',
    "alerts": '<path d="M12 3 2 21h20L12 3zM12 9v5M12 17v1"/>',
    "incidents": '<path d="M3 6h7l2 3h9v12H3zM3 6V3h7l2 3"/>',
    "risk": '<path d="M12 3 3 7v6c0 5 9 9 9 9s9-4 9-9V7l-9-4zM12 8v6M12 17v1"/>',
}


def e(value: Any) -> str:
    return escape(str(value), quote=True)


def _svg_image(svg: str, alt: str = "") -> str:
    """DOMPurify strips inline SVG; an inert SVG image preserves vector rendering."""
    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    decorative = ' aria-hidden="true"' if not alt else ''
    return f'<img src="data:image/svg+xml;base64,{encoded}" alt="{e(alt)}"{decorative} style="display:block;width:100%;height:100%">'


def icon(name: str, *, risk: bool = False) -> str:
    color = "#ff8990" if risk else "#46c8ba"
    return _svg_image(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.5">{ICONS[name]}</svg>')


def apply_styles() -> None:
    st.html(f"<style>{Path(__file__).with_name('styles.css').read_text()}</style>")


def brand() -> None:
    st.html(f'<div class="soc-brand"><span class="soc-brand-mark">{icon("risk")}</span><div><div class="soc-brand-name">GSEC SENTINEL</div><div class="soc-brand-sub">SECURITY OPERATIONS</div></div></div>')


def badge(text: str, variant: str = "neutral") -> str:
    if variant not in {"neutral", "accent", "danger", "warning"}:
        variant = "neutral"
    return f'<span class="soc-badge soc-badge-{variant}">{e(text)}</span>'


def topbar(page: str, dataset_id: str, kind: str, *, as_of: datetime | None = None,
           loaded_at: datetime | None = None, fetched: bool = False) -> None:
    tags = [badge("SINTÉTICO · PRUEBA" if kind == "synthetic" else "OFICIAL", "accent"),
            badge(dataset_id or "Sin dataset")]
    if as_of:
        tags.append(badge("REPLAY · " + as_of.strftime("%d %b %H:%M UTC"), "accent"))
    elif loaded_at:
        tags.append(badge(("API · " if fetched else "MEMORIA · ") + loaded_at.strftime("%H:%M:%S UTC")))
    st.html(f'<header class="soc-topbar"><div><div class="soc-eyebrow">WORKSTATION / OPERATIONS</div><h1>{e(page)}</h1></div><div class="soc-topbar-meta">{"".join(tags)}</div></header>')


def panel_heading(title: str, detail: str = "") -> None:
    st.html(f'<div class="soc-panel-heading"><h2>{e(title)}</h2><span>{e(detail)}</span></div>')


def kpis(events: list[dict], alerts: list[dict], incidents: list[dict]) -> None:
    items = [("Eventos consultados", len(events), "Snapshot de la partición", "events", False),
             ("Alertas detectadas", len(alerts), "Última ejecución de esta vista", "alerts", False),
             ("Incidentes", len(incidents), "Con evidencia correlacionada", "incidents", False),
             ("Alta / crítica", sum(a.get("severity") in {"high", "critical"} for a in alerts), "Alertas que requieren revisión", "risk", any(a.get("severity") in {"high", "critical"} for a in alerts))]
    cards = []
    for label, value, detail, glyph, risk in items:
        cards.append(f'<article class="soc-kpi{" soc-kpi-risk" if risk else ""}"><span class="soc-kpi-icon">{icon(glyph, risk=risk)}</span><div class="soc-kpi-label">{e(label)}</div><div class="soc-kpi-value">{value:,}</div><div class="soc-kpi-detail">{e(detail)}</div></article>')
    st.html('<section class="soc-kpi-grid" aria-label="Indicadores de esta consulta">' + ''.join(cards) + '</section>')


def severity_distribution(alerts: list[dict]) -> None:
    counts = Counter(a.get("severity", "info") for a in alerts)
    levels = [("critical", "Crítica", "#ff8990"), ("high", "Alta", "#f5a3a8"), ("medium", "Media", "#f7c568"), ("low", "Baja", "#46c8ba"), ("info", "Info", "#a9b7c9")]
    total = len(alerts)
    circles, legend, offset = [], [], 0.0
    for level, label, color in levels:
        count = counts.get(level, 0)
        proportion = count / total * 100 if total else 0
        if count:
            circles.append(f'<circle cx="60" cy="60" r="49" fill="none" stroke="{color}" stroke-width="7" pathLength="100" stroke-dasharray="{proportion} {100-proportion}" stroke-dashoffset="{-offset}" transform="rotate(-90 60 60)"/>')
        offset += proportion
        if level != "info" or count:
            legend.append(f'<div><span><i style="background:{color}"></i>{label}</span><b>{count}</b></div>')
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120"><circle cx="60" cy="60" r="49" fill="none" stroke="#293442" stroke-width="7"/>{"".join(circles)}<text x="60" y="61" text-anchor="middle" fill="#e4eaf2" font-family="monospace" font-size="25" font-weight="600">{total}</text><text x="60" y="79" text-anchor="middle" fill="#a9b7c9" font-family="sans-serif" font-size="10">ALERTAS</text></svg>'
    alt = f"{total} alertas, distribución por severidad. " + ". ".join(f"{label}: {counts.get(level, 0)}" for level, label, _ in levels)
    st.html(f'<div class="soc-distribution"><div style="width:120px;height:120px">{_svg_image(svg, alt)}</div><div class="soc-distribution-legend">{"".join(legend)}</div></div>')


def entities_summary(events: list[dict]) -> None:
    counts = Counter(row["Tipo"] for row in entity_rows(events))
    items = ''.join(f'<div class="soc-summary-item"><span class="soc-summary-number">{counts.get(kind,0)}</span><span class="soc-summary-label">{kind}</span></div>' for kind in ("Usuario", "Host", "IP", "Archivo"))
    st.html(f'<div class="soc-summary">{items}<div class="soc-summary-note">Entidades únicas con atributos explícitos. Su presencia no demuestra compromiso.</div></div>')


def alert_summary(alert: dict) -> None:
    severity = alert.get("severity", "info")
    variant = "danger" if severity in {"critical", "high"} else "warning" if severity == "medium" else "accent"
    st.html(f'<div class="soc-alert-row">{badge(severity_label(severity), variant)}<div class="soc-alert-title">{e(alert["title"])}</div><div class="soc-alert-meta">{e(alert.get("rule_id", ""))} · {len(alert.get("evidence_event_ids", []))} eventos de evidencia</div></div>')


def activity_feed(events: list[dict]) -> None:
    rows = []
    for event in sorted(events, key=lambda item: (parse_utc(item["timestamp_utc"]), item["event_id"]), reverse=True)[:6]:
        attrs = event.get("attributes", {})
        subject = attrs.get("host") or attrs.get("user") or event.get("source", "")
        stamp = parse_utc(event["timestamp_utc"])
        rows.append(f'<div class="soc-feed-item"><time class="soc-feed-time" datetime="{e(stamp.isoformat())}" title="{e(stamp.isoformat())}">{e(stamp.strftime("%d %b"))}<br>{e(stamp.strftime("%H:%M:%S"))}</time><div><div class="soc-feed-type">{e(event["event_type"])}</div><div class="soc-feed-subject">{e(subject)} · {e(event.get("source", ""))}</div></div></div>')
    st.html('<div class="soc-feed">' + ''.join(rows) + '</div>' if rows else '<div class="soc-empty">No hay eventos en esta partición.</div>')


def evidence_header(event: dict) -> None:
    attrs = event.get("attributes", {})
    subject = attrs.get("host") or attrs.get("user") or event.get("source", "")
    st.html(f'<div class="soc-evidence-header"><strong>{e(event["event_type"])}</strong><p>{e(subject)} · {e(parse_utc(event["timestamp_utc"]).strftime("%d %b %H:%M:%S UTC"))}</p></div>')


def status_strip(incident_title: str, event_count: int, alert_count: int, *, historical: bool = False) -> None:
    st.html(f'<div class="soc-status-strip"><span><strong>{e(incident_title)}</strong></span><span>{event_count} eventos · {alert_count} alertas</span><span>{"CORTE HISTÓRICO / TRANSITORIO" if historical else "EVIDENCIA CORRELACIONADA"}</span></div>')


def attributes_summary(attributes: dict) -> None:
    pairs = ''.join(f'<div><dt>{e(key)}</dt><dd>{e(value)}</dd></div>' for key, value in list(attributes.items())[:8])
    st.html(f'<dl class="soc-attributes">{pairs}</dl>')
    if len(attributes) > 8:
        st.caption(f"{len(attributes)} atributos disponibles en el evento normalizado completo.")
