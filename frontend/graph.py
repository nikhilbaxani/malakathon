"""Bounded, offline attack graph view with inert telemetry text."""

from __future__ import annotations

import base64
import json
import math
from datetime import datetime
from typing import Any

from frontend.replay import parse_utc


MAX_NODES = 120
MAX_EDGES = 800
TYPE_COLORS = {
    "EVENT": "#4285f4",
    "ALERT": "#fbbc04",
    "INCIDENT": "#ea4335",
    "USER": "#34a853",
    "HOST": "#8e44ad",
    "IP": "#00acc1",
    "FILE": "#795548",
    "PROCESS": "#f57c00",
}


def missing_optional_types(node_types: list[str]) -> list[str]:
    present = {node_type.casefold() for node_type in node_types}
    return [kind.upper() for kind in ("ip", "file", "process") if kind not in present]


def graph_view(
    graph: dict[str, Any], *, selected_types: set[str] | None = None,
    visible_event_ids: set[str] | None = None, as_of: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Bound and filter a graph; replay never displays edges backed by later events."""
    raw_nodes = graph.get("nodes", [])
    raw_edges = graph.get("edges", [])
    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        raise ValueError("El grafo debe contener listas de nodos y aristas")
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for node in raw_nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            continue
        node_id = node["id"]
        node_type = str(node.get("type", "OTRO"))
        if node_id in seen or (selected_types is not None and node_type not in selected_types):
            continue
        seen.add(node_id)
        nodes.append(node)
        if len(nodes) == MAX_NODES:
            break
    ids = {node["id"] for node in nodes}
    edges: list[dict[str, Any]] = []
    for edge in raw_edges:
        if not isinstance(edge, dict) or edge.get("source") not in ids or edge.get("target") not in ids:
            continue
        evidence = edge.get("evidence_event_ids", [])
        if not isinstance(evidence, list):
            continue
        if visible_event_ids is not None and not set(evidence) <= visible_event_ids:
            continue
        if as_of is not None:
            try:
                if any(
                    edge.get(field) and parse_utc(edge[field]) > as_of
                    for field in ("time_start_utc", "time_end_utc")
                ):
                    continue
            except (ValueError, TypeError):
                continue
        edges.append(edge)
        if len(edges) == MAX_EDGES:
            break
    truncated = len(raw_nodes) > MAX_NODES or len(raw_edges) > MAX_EDGES
    return nodes, edges, truncated


def _positions(nodes: list[dict[str, Any]], layout: str) -> dict[str, tuple[float, float]]:
    if not nodes:
        return {}
    if layout == "Capas":
        types = sorted({str(node.get("type", "OTRO")) for node in nodes})
        grouped = {kind: [node for node in nodes if str(node.get("type", "OTRO")) == kind] for kind in types}
        positions = {}
        for row, kind in enumerate(types):
            group = grouped[kind]
            y = 85 + row * 530 / max(len(types) - 1, 1)
            for column, node in enumerate(group):
                x = 80 + column * 1040 / max(len(group) - 1, 1)
                positions[node["id"]] = (x, y)
        return positions
    count = len(nodes)
    return {
        node["id"]: (
            600 + 475 * math.cos(2 * math.pi * index / count),
            350 + 270 * math.sin(2 * math.pi * index / count),
        )
        for index, node in enumerate(nodes)
    }


def render_graph_html(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], *, layout: str = "Capas") -> str:
    """Return self-contained HTML. Untrusted values are base64 JSON, then textContent."""
    positions = _positions(nodes, layout)
    payload = {
        "nodes": [{**node, "x": positions[node["id"]][0], "y": positions[node["id"]][1]} for node in nodes],
        "edges": edges,
        "colors": TYPE_COLORS,
    }
    encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")).decode("ascii")
    return """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><style>
body{margin:0;font:14px system-ui,sans-serif;color:#e8eaed;background:#111827}
#toolbar{display:flex;gap:8px;padding:8px 12px;align-items:center}
button{background:#253247;border:1px solid #526174;color:#fff;border-radius:5px;padding:5px 10px;cursor:pointer}
#canvas{width:100%;height:520px;background:#182334;cursor:grab;touch-action:none}
#canvas:active{cursor:grabbing} #legend{display:flex;gap:14px;flex-wrap:wrap;padding:8px 12px}
.swatch{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:5px}
#details{margin:0;padding:10px 12px;height:115px;overflow:auto;white-space:pre-wrap;background:#101925}
</style></head><body>
<div id="toolbar"><button id="zoomIn">+</button><button id="zoomOut">−</button><button id="reset">Restablecer</button><span>Arrastra para mover · rueda para ampliar · pulsa un nodo o arista</span></div>
<svg id="canvas" viewBox="0 0 1200 700" role="img" aria-label="Grafo de ataque interactivo">
<defs><marker id="arrow" markerWidth="7" markerHeight="7" refX="21" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3 z" fill="#78879a"/></marker></defs>
<g id="world"></g></svg><div id="legend"></div><pre id="details">Selecciona un nodo o una arista para inspeccionar sus atributos y evidencia.</pre>
<script>
const encoded = """ + json.dumps(encoded) + """;
const bytes = Uint8Array.from(atob(encoded), ch => ch.charCodeAt(0));
const data = JSON.parse(new TextDecoder().decode(bytes));
const ns = 'http://www.w3.org/2000/svg', svg = document.getElementById('canvas');
const world = document.getElementById('world'), details = document.getElementById('details');
const byId = new Map(data.nodes.map(node => [node.id, node]));
let scale = 1, dx = 0, dy = 0, drag = null;
function apply(){world.setAttribute('transform', `translate(${dx} ${dy}) scale(${scale})`)}
function element(name, attributes){const e=document.createElementNS(ns,name);for(const [k,v] of Object.entries(attributes))e.setAttribute(k,String(v));return e}
function show(value){details.textContent=JSON.stringify(value,null,2)}
for(const edge of data.edges){
  const a=byId.get(edge.source), b=byId.get(edge.target); if(!a||!b)continue;
  const line=element('line',{x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:'#78879a','stroke-width':2,'stroke-dasharray':edge.basis==='derived'?'7 4':'','marker-end':'url(#arrow)'});
  line.style.cursor='pointer'; line.addEventListener('click',()=>show(edge)); world.appendChild(line);
}
for(const node of data.nodes){
  const group=element('g',{}), color=data.colors[String(node.type).toUpperCase()]||'#9aa5b1';
  const circle=element('circle',{cx:node.x,cy:node.y,r:18,fill:color,stroke:'#f8fafc','stroke-width':2});
  const label=element('text',{x:node.x,y:node.y+37,fill:'#f8fafc','text-anchor':'middle','font-size':12});
  label.textContent=String(node.label||node.id).slice(0,24);
  const title=element('title',{});title.textContent=String(node.label||node.id);
  group.append(circle,label,title);group.style.cursor='pointer';group.addEventListener('click',()=>show(node));world.appendChild(group);
}
for(const type of [...new Set(data.nodes.map(node=>String(node.type)))].sort()){
  const item=document.createElement('span'), swatch=document.createElement('span');swatch.className='swatch';
  swatch.style.background=data.colors[type.toUpperCase()]||'#9aa5b1';item.appendChild(swatch);
  item.appendChild(document.createTextNode(type));document.getElementById('legend').appendChild(item);
}
function zoom(factor){scale=Math.max(.35,Math.min(4,scale*factor));apply()}
document.getElementById('zoomIn').onclick=()=>zoom(1.2);
document.getElementById('zoomOut').onclick=()=>zoom(1/1.2);
document.getElementById('reset').onclick=()=>{scale=1;dx=0;dy=0;apply()};
svg.addEventListener('wheel',event=>{event.preventDefault();zoom(event.deltaY<0?1.1:1/1.1)},{passive:false});
svg.addEventListener('pointerdown',event=>{drag={x:event.clientX,y:event.clientY};svg.setPointerCapture(event.pointerId)});
svg.addEventListener('pointermove',event=>{if(!drag)return;const box=svg.getBoundingClientRect();dx+=(event.clientX-drag.x)*1200/box.width;dy+=(event.clientY-drag.y)*700/box.height;drag={x:event.clientX,y:event.clientY};apply()});
svg.addEventListener('pointerup',()=>{drag=null});svg.addEventListener('pointercancel',()=>{drag=null});
</script></body></html>"""
