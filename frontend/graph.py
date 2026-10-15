"""Bounded, offline attack graph view with inert telemetry text."""

from __future__ import annotations

import base64
import json
import math
from datetime import datetime
from typing import Any

import networkx as nx

from frontend.replay import parse_utc


MAX_NODES = 120
MAX_EDGES = 800
TYPE_COLORS = {
    "EVENT": "#67e8f9", "ALERT": "#93c5fd", "INCIDENT": "#c4b5fd",
    "USER": "#99f6e4", "HOST": "#a5b4fc", "IP": "#7dd3fc",
    "FILE": "#cbd5e1", "PROCESS": "#d8b4fe",
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


def _positions(nodes: list[dict[str, Any]], layout: str, edges: list[dict[str, Any]] | None = None) -> dict[str, tuple[float, float]]:
    if not nodes:
        return {}
    if layout == "Relacional":
        graph = nx.Graph()
        graph.add_nodes_from(node["id"] for node in nodes)
        graph.add_edges_from((edge["source"], edge["target"]) for edge in edges or []
                             if edge.get("source") in graph and edge.get("target") in graph)
        coordinates = nx.spring_layout(graph, seed=17, iterations=80, k=1.2 / math.sqrt(len(nodes)))
        positions = {node_id: [600 + float(position[0]) * 470, 350 + float(position[1]) * 265]
                     for node_id, position in coordinates.items()}
        # Small investigations need room for entity labels as well as circles.
        # Deterministic separation preserves the spring layout's relationships;
        # dense graphs still rely on filters and zoom rather than a false guarantee.
        if len(nodes) <= 24:
            minimum = 230 * math.sqrt(10 / max(10, len(nodes)))
            ordered_ids = sorted(positions)
            for _ in range(80):
                moved = False
                for index, first in enumerate(ordered_ids):
                    for second in ordered_ids[index + 1:]:
                        a, b = positions[first], positions[second]
                        dx, dy = b[0] - a[0], b[1] - a[1]
                        distance = math.hypot(dx, dy)
                        if distance >= minimum:
                            continue
                        if distance < .001:
                            dx, dy, distance = 1.0, 1.0, math.sqrt(2)
                        shift = (minimum - distance) / 2 + .1
                        a[0] -= dx / distance * shift
                        a[1] -= dy / distance * shift
                        b[0] += dx / distance * shift
                        b[1] += dy / distance * shift
                        moved = True
                for position in positions.values():
                    position[0] = min(1080, max(120, position[0]))
                    position[1] = min(600, max(85, position[1]))
                if not moved:
                    break
        return {node_id: (position[0], position[1]) for node_id, position in positions.items()}
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


def render_graph_html(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]], *, layout: str = "Capas",
    evidence: list[dict[str, Any]] | None = None,
) -> str:
    """Self-contained SVG. Untrusted values remain base64 JSON, then textContent.

    The iframe can inspect normalized evidence locally. Python-side original-file
    retrieval is deliberately controlled by the equivalent native relation selector.
    """
    positions = _positions(nodes, layout, edges)
    payload = {
        "nodes": [{**node, "x": positions[node["id"]][0], "y": positions[node["id"]][1]} for node in nodes],
        "edges": edges, "colors": TYPE_COLORS,
        "evidence": {event["event_id"]: event for event in evidence or []},
    }
    encoded = base64.b64encode(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")).decode("ascii")
    return """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>
:root{color-scheme:dark;--bg:#0b0f15;--surface:#101721;--text:#e4eaf2;--muted:#a9b7c9;--accent:#46c8ba}
*{box-sizing:border-box}body{margin:0;font:13px system-ui,sans-serif;color:var(--text);background:var(--bg)}
#toolbar{display:flex;flex-wrap:wrap;gap:6px;padding:8px;align-items:center;border-bottom:1px solid #293442}
button,select{background:var(--surface);border:1px solid #445469;color:var(--text);border-radius:4px;padding:5px 8px;min-height:30px;cursor:pointer}
button:focus-visible,select:focus-visible,svg [tabindex]:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
#canvas{width:100%;height:440px;background-color:var(--bg);background-image:radial-gradient(#29344288 .8px,transparent .8px);background-size:20px 20px;cursor:grab;touch-action:none}
#canvas:active{cursor:grabbing}#legend{display:flex;gap:10px;flex-wrap:wrap;padding:6px 8px;color:var(--muted)}
.swatch{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:4px}
#inspection{padding:10px;min-height:110px;max-height:180px;overflow:auto;border-top:1px solid #293442;background:var(--surface)}
#summary{margin:0 0 6px;overflow-wrap:anywhere}#eventPicker{max-width:100%;width:100%}
#details{margin:6px 0;font:13px ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
#technical{font:12px ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.relation-label{opacity:0;pointer-events:none}.relation:hover .relation-label,.relation:focus .relation-label,.relation.selected .relation-label{opacity:1}
.relation .connection{opacity:.7}.relation:hover .connection,.relation:focus .connection,.relation.selected .connection{opacity:1;stroke:var(--accent);stroke-width:2}
.node.selected circle,.node.related circle,.node:hover circle,.node:focus circle{stroke:var(--accent);stroke-width:3}
.caption-bg{fill:#141b25;stroke:#293442;stroke-width:1;vector-effect:non-scaling-stroke}.node.selected .caption-bg,.node.related .caption-bg{stroke:var(--accent);fill:#142c2d}
.relation.related .connection{opacity:1;stroke:var(--accent);stroke-width:1.5}
#legend .relation-key{display:inline-flex;gap:6px;align-items:center}#legend .relation-key i{display:inline-block;width:18px;border-top:2px solid var(--accent)}#legend .relation-key.derived i{border-top-style:dashed}
#toolbar .toolbar-label{color:var(--muted);font-size:12px;margin-right:auto}#toolbar button{font-size:12px}#inspection details{margin-top:7px;color:var(--muted)}#inspection summary{cursor:pointer}
</style></head><body>
<div id="toolbar" role="toolbar" aria-label="Controles del grafo">
<span class="toolbar-label">Explorar relaciones</span><button id="zoomIn" aria-label="Ampliar grafo">+ Zoom</button><button id="zoomOut" aria-label="Reducir grafo">− Zoom</button>
<button id="panLeft" aria-label="Mover grafo a la izquierda">←</button><button id="panRight" aria-label="Mover grafo a la derecha">→</button>
<button id="panUp" aria-label="Mover grafo hacia arriba">↑</button><button id="panDown" aria-label="Mover grafo hacia abajo">↓</button>
<button id="reset" aria-label="Restablecer">Ajustar / centrar</button></div>
<svg id="canvas" viewBox="0 0 1200 700" role="group" aria-label="Grafo de ataque interactivo: nodos y relaciones. Tab para seleccionar; Enter para inspeccionar.">
<defs><marker id="arrow" markerWidth="7" markerHeight="7" refX="30" refY="3.5" orient="auto"><path d="M0,0 L0,7 L7,3.5 z" fill="#46c8ba"/></marker></defs>
<g id="world"></g></svg><div id="legend"></div>
<div id="inspection"><p id="summary" role="status" aria-live="polite">Selecciona un nodo o una relación. Usa el selector exterior para abrir su archivo original.</p>
<label for="eventPicker">Evidencia normalizada de la relación</label><select id="eventPicker" disabled><option>Selecciona una relación con evidencia</option></select>
<details><summary>Evento normalizado completo</summary><pre id="details"></pre></details><details><summary>Identificadores y proveniencia</summary><pre id="technical"></pre></details></div>
<script>
const encoded = """ + json.dumps(encoded) + """;
const bytes = Uint8Array.from(atob(encoded), ch => ch.charCodeAt(0));
const data = JSON.parse(new TextDecoder().decode(bytes));
const ns='http://www.w3.org/2000/svg',svg=document.getElementById('canvas');
const world=document.getElementById('world'),details=document.getElementById('details');
const summary=document.getElementById('summary'),picker=document.getElementById('eventPicker'),technical=document.getElementById('technical');
const byId=new Map(data.nodes.map(node=>[node.id,node]));
const nodeElements=new Map(),edgeElements=[];
const typeNames={EVENT:'EVENTO',ALERT:'ALERTA',INCIDENT:'INCIDENTE',USER:'USUARIO',HOST:'HOST',IP:'IP',FILE:'ARCHIVO',PROCESS:'PROCESO'};
const iconPaths={EVENT:'M5 3h14v18H5zM8 8h8M8 12h8M8 16h5',ALERT:'M12 3 2 21h20zM12 9v5M12 17v1',INCIDENT:'M3 6h7l2 3h9v12H3z',USER:'M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0M4 21v-3a8 8 0 0 1 16 0v3',HOST:'M3 3h18v14H3zM8 21h8M12 17v4',IP:'M3 5h18v14H3zM3 10h18M7 15h1M11 15h1',FILE:'M5 2h9l5 5v15H5zM14 2v6h5',PROCESS:'M7 7h10v10H7zM3 9h4M3 15h4M17 9h4M17 15h4M9 3v4M15 3v4M9 17v4M15 17v4'};
let scale=1,dx=0,dy=0,drag=null;
function fitLabels(){
 const matrix=world.getScreenCTM();if(!matrix)return;
 const ratio=Math.hypot(matrix.a,matrix.b);if(!ratio)return;
 for(const circle of world.querySelectorAll('.node circle'))circle.setAttribute('r',20/ratio);
 for(const label of world.querySelectorAll('.relation-label'))label.setAttribute('font-size',13/ratio);
 for(const group of world.querySelectorAll('.node')){
  const x=Number(group.dataset.x),y=Number(group.dataset.y),label=group.querySelector('.node-caption'),plate=group.querySelector('.caption-bg');
  const icon=group.querySelector('.node-icon');icon.setAttribute('transform',`translate(${x-9/ratio} ${y-9/ratio}) scale(${.75/ratio})`);
  label.setAttribute('font-size',13/ratio);label.setAttribute('x',x);
  label.setAttribute('y',y+36/ratio);
  for(const[index,line]of [...label.children].entries()){line.setAttribute('x',x);line.setAttribute('dy',index?16/ratio:0)}
  let box=label.getBBox();
  const shift=Math.max(22-box.x,Math.min(0,1178-box.x-box.width));
  if(shift){label.setAttribute('x',x+shift);for(const line of label.children)line.setAttribute('x',x+shift);box=label.getBBox()}
  if(box.y+box.height>678){label.setAttribute('y',y-28/ratio-box.height);box=label.getBBox()}
  plate.setAttribute('x',box.x-7/ratio);plate.setAttribute('y',box.y-5/ratio);plate.setAttribute('width',box.width+14/ratio);plate.setAttribute('height',box.height+10/ratio);plate.setAttribute('rx',4/ratio);
 }
}
function apply(){world.setAttribute('transform',`translate(${dx} ${dy}) scale(${scale})`);fitLabels()}
function element(name,attributes){const e=document.createElementNS(ns,name);for(const[k,v]of Object.entries(attributes))e.setAttribute(k,String(v));return e}
function activate(e,callback){e.setAttribute('tabindex','0');e.setAttribute('role','button');e.addEventListener('click',callback);e.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();callback()}})}
function relationName(edge,index){const a=byId.get(edge.source),b=byId.get(edge.target);return `R${String(index+1).padStart(3,'0')} · ${a.label} → ${b.label} · ${edge.type||''} · ${edge.basis==='derived'?'DERIVADA':'OBSERVADA'}`}
function selectedEvidence(){const event=data.evidence[picker.value];details.textContent=event?JSON.stringify(event,null,2):''}
function show(value,title,owner){
 if(owner){
  for(const selected of world.querySelectorAll('.selected,.related'))selected.classList.remove('selected','related');owner.classList.add('selected');
  const adjacent=value.source?[value.source,value.target]:[value.id];
  for(const edgeEntry of edgeElements){if(adjacent.includes(edgeEntry.edge.source)||adjacent.includes(edgeEntry.edge.target)){
   if(!value.source)edgeEntry.element.classList.add('related');
   for(const id of [edgeEntry.edge.source,edgeEntry.edge.target])if(!value.source||adjacent.includes(id))nodeElements.get(id)?.classList.add('related');
  }}
 }
 summary.textContent=title;technical.textContent=JSON.stringify(value,null,2);picker.replaceChildren();
 const ids=(value.evidence_event_ids||[]).filter(id=>data.evidence[id]);picker.disabled=ids.length===0;
 if(!ids.length){const option=document.createElement('option');option.textContent='Sin evidencia de relación seleccionada';picker.appendChild(option)}
 for(const[idIndex,id]of ids.entries()){const event=data.evidence[id],option=document.createElement('option');option.value=id;option.textContent=`${idIndex+1}. ${event.timestamp_utc} · ${event.event_type}`;picker.appendChild(option)}
 selectedEvidence();
}
picker.addEventListener('change',selectedEvidence);
for(const[index,edge]of data.edges.entries()){
 const a=byId.get(edge.source),b=byId.get(edge.target);if(!a||!b)continue;
 const group=element('g',{'class':'relation','aria-label':relationName(edge,index)});
 const line=element('line',{'class':'connection',x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:'#46c8ba','stroke-width':1.25,'vector-effect':'non-scaling-stroke','stroke-dasharray':edge.basis==='derived'?'5 4':'','marker-end':'url(#arrow)'});
 const hit=element('line',{x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:'transparent','stroke-width':18});
 const label=element('text',{'class':'relation-label',x:(a.x+b.x)/2,y:(a.y+b.y)/2-5,fill:'#e4eaf2','font-size':13,'data-minimum':13,'text-anchor':'middle','paint-order':'stroke',stroke:'#0b0f15','stroke-width':4});
 label.textContent=`R${String(index+1).padStart(3,'0')}`;group.append(line,hit,label);group.style.cursor='pointer';activate(group,()=>show(edge,relationName(edge,index),group));world.appendChild(group);edgeElements.push({edge,element:group});
}
for(const node of data.nodes){
 const kind=String(node.type).toUpperCase(),color=data.colors[kind]||'#a9b7c9';
 const group=element('g',{'class':'node','data-x':node.x,'data-y':node.y,'aria-label':`${typeNames[kind]||kind} · ${node.label}`});
 const circle=element('circle',{cx:node.x,cy:node.y,r:24,fill:'#102528',stroke:color,'stroke-width':1.5,'vector-effect':'non-scaling-stroke'});
 const icon=element('g',{'class':'node-icon',fill:'none',stroke:color,'stroke-width':1.5,'stroke-linecap':'round','stroke-linejoin':'round'});
 icon.appendChild(element('path',{d:iconPaths[kind]||iconPaths.EVENT}));
 const plate=element('rect',{'class':'caption-bg'});
 const label=element('text',{'class':'node-caption',x:node.x,y:node.y+37,fill:'#e4eaf2','text-anchor':'middle','font-size':13,'data-minimum':13,'data-node-y':node.y});
 const typeLine=element('tspan',{'font-weight':600,fill:'#a9b7c9'});typeLine.textContent=typeNames[kind]||kind;label.appendChild(typeLine);
 const fullLabel=String(node.label||'Entidad');let remaining=fullLabel;
 for(let lineIndex=0;lineIndex<2&&remaining;lineIndex++){
  let limit=remaining.length>22?Math.max(remaining.lastIndexOf(' ',22),remaining.lastIndexOf('_',22),14):remaining.length;limit=Math.min(limit,22);
  const line=element('tspan',{});line.textContent=remaining.slice(0,limit)+(lineIndex===1&&remaining.length>limit?'…':'');label.appendChild(line);remaining=remaining.slice(limit).trim();
 }
 const title=element('title',{});title.textContent=fullLabel;
 group.append(circle,icon,plate,label,title);group.style.cursor='pointer';activate(group,()=>show(node,`${typeNames[kind]||kind} · ${node.label}`,group));world.appendChild(group);nodeElements.set(node.id,group);
}
for(const type of [...new Set(data.nodes.map(node=>String(node.type)))].sort()){
 const item=document.createElement('span'),swatch=document.createElement('span');swatch.className='swatch';swatch.setAttribute('aria-hidden','true');
 swatch.style.background=data.colors[type.toUpperCase()]||'#a7b6c8';item.appendChild(swatch);item.appendChild(document.createTextNode(typeNames[type.toUpperCase()]||type));document.getElementById('legend').appendChild(item);
}
for(const[derived,text]of [[false,'Observada'],[true,'Derivada']]){const item=document.createElement('span');item.className='relation-key'+(derived?' derived':'');const line=document.createElement('i');line.setAttribute('aria-hidden','true');item.append(line,document.createTextNode(text));document.getElementById('legend').appendChild(item)}
function zoom(factor){scale=Math.max(.35,Math.min(4,scale*factor));apply()}
document.getElementById('zoomIn').onclick=()=>zoom(1.2);document.getElementById('zoomOut').onclick=()=>zoom(1/1.2);
for(const[id,x,y]of [['panLeft',-80,0],['panRight',80,0],['panUp',0,-80],['panDown',0,80]])document.getElementById(id).onclick=()=>{dx+=x;dy+=y;apply()};
document.getElementById('reset').onclick=()=>{scale=1;dx=0;dy=0;apply()};
svg.addEventListener('wheel',event=>{event.preventDefault();zoom(event.deltaY<0?1.1:1/1.1)},{passive:false});
svg.addEventListener('pointerdown',event=>{if(event.target!==svg)return;drag={x:event.clientX,y:event.clientY};svg.setPointerCapture(event.pointerId)});
svg.addEventListener('pointermove',event=>{if(!drag)return;const box=svg.getBoundingClientRect();dx+=(event.clientX-drag.x)*1200/box.width;dy+=(event.clientY-drag.y)*700/box.height;drag={x:event.clientX,y:event.clientY};apply()});
svg.addEventListener('pointerup',()=>{drag=null});svg.addEventListener('pointercancel',()=>{drag=null});
new ResizeObserver(fitLabels).observe(svg);fitLabels();
</script></body></html>"""
