# Propuesta de Implementación: Integración TypeSafe Jev (v1.13.0) en GSEC Sentinel

> **Documento de diseño y discusión técnica**  
> **Participantes:** Usuario, Antigravity, Codex (`soc_ai`, `soc_reviewer`)  
> **Fecha:** 14 de octubre de 2026  
> **Estado:** Borrador de propuesta (pendiente de análisis conjunto)

---

## 1. Contexto y Justificación

En la fase inicial (MVP), el módulo `backend/ai/` implementó un adaptador preliminar con mocks que únicamente enviaba conteos agregados de alertas (`alert_count`, `severity_counts`) y formulaba una pregunta básica con diccionarios genéricos.

Esta propuesta define la integración con la **API tipada real del SDK de TypeSafe (`typesafe-sdk`)**, utilizando primitivas formales (`Choice`, `Score`, `Noul`) y la versión fijada `jev-1.13.0` para dotar a GSEC Sentinel de un **triaje de incidentes de Nivel 1/2 asistido por IA**, explicable, probabilístico y alineado con los contratos y normas del SOC.

---

## 2. API Oficial de TypeSafe y Patrón de Referencia

El patrón de integración propuesto se basa en la evaluación paralela en una única llamada mediante `client.system_one`:

```python
import os
from typesafe_sdk import TypeSafeClient, Choice, Score, Noul

# Fijación de modelo recomendada para reproducibilidad
with TypeSafeClient(model="jev-1.13.0", api_key=os.getenv("TYPESAFE_API_KEY")) as client:
    
    # 1. 'state' estructurado del incidente sintético
    alerta_siem = {
        "timestamp": "2026-10-14T15:22:10Z",
        "host": "SRV-FINANCE-02",
        "user": "svc_backup",
        "process": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
        "network_out": "185.220.101.45:443",
        "edr_context": "El proceso hijo fue lanzado por sqlservr.exe fuera de la ventana de mantenimiento."
    }

    # 2. Evaluación multi-criterio en paralelo (System 1)
    response = client.system_one(
        state=alerta_siem,
        questions={
            "tactica_mitre": Choice(
                instructions="¿Cuál es la táctica principal observada en este evento?",
                criteria={
                    "execution": "Ejecución de código o scripts maliciosos/ofuscados",
                    "persistence": "Creación de tareas programadas, cuentas o llaves de registro",
                    "exfiltration": "Transferencia anómala de datos hacia una IP externa",
                    "benign_admin": "Actividad legítima de administración o mantenimiento"
                }
            ),
            "severidad": Score(
                instructions="Evalúa el nivel de riesgo operativo de esta alerta.",
                criteria=[
                    "Nivel 0 (Bajo): Ruido normal o tarea administrativa conocida",
                    "Nivel 1 (Medio): Comportamiento inusual pero sin indicadores claros de compromiso",
                    "Nivel 2 (Alto): Actividad sospechosa en servidor sensible o uso de comandos ofuscados",
                    "Nivel 3 (Crítico): Compromiso activo confirmado en un activo crítico con conexión externa"
                ]
            ),
            "aislar_host": Noul(
                instructions="¿El evento muestra ejecución remota de comandos sobre un servidor crítico que justifique aislar el host de la red?",
                criteria={
                    "true": "Hay ejecución ofuscada desde un servicio (como SQL) conectándose al exterior",
                    "false": "Es un script rutinario o no hay evidencia de compromiso activo"
                }
            )
        }
    )

# 3. Lectura tipada de respuestas
tactica = response.answers["tactica_mitre"]      # .choice (str), .confidence (float 0.0-1.0)
severidad = response.answers["severidad"]        # .score (float 0.0-3.0)
aislar = response.answers["aislar_host"]          # .noul (probabilidad bayesiana 0.0-1.0)
```

---

## 3. Mapeo a los Contratos de GSEC Sentinel

La integración debe satisfacer el contrato de datos `TriageResult` definido en `backend/models.py`:

```python
class TriageResult(ContractModel):
    triage_id: Identifier
    incident_id: Identifier
    engine: Literal["deterministic", "jev"]
    assessment: Literal["needs_review", "likely_true_positive", "likely_false_positive"]
    summary: Identifier
    rationale: Identifier
    generated_at: AwareDatetime
    evidence_event_ids: EvidenceIds
```

### 3.1. Reglas de Mapeo de Umbrales

| Campo en `TriageResult` | Origen / Lógica basada en Jev |
| :--- | :--- |
| **`assessment`** | • `likely_true_positive`: si `severidad.score >= 2.0` y `tactica.confidence >= 0.70`<br>• `likely_false_positive`: si `severidad.score <= 0.5` y `tactica.choice == "benign_admin"`<br>• `needs_review`: en cualquier otro caso o ante incertidumbre. |
| **`summary`** | Texto enriquecido: `f"Jev ({tactica.choice.upper()}): Severidad {severidad.score:.1f}/3.0 (confianza {tactica.confidence:.0%}). Sugerencia aislamiento: {aislar.noul:.0%}."` |
| **`rationale`** | Detalle de las preguntas evaluadas y justificación táctica de TypeSafe para el analista. |
| **`evidence_event_ids`** | Se conservan estrictamente los IDs de evidencia del incidente evaluado (sin inventar ni modificar). |

### 3.2. Adaptación del Flujo de Contención (SOAR / Simulación)

* **Regla estricta:** En GSEC Sentinel está prohibida la contención real automática sin autorización.
* **Flujo adaptado:**
  1. Si `aislar.noul >= 0.85`: Jev **no aísla** el host directamente.
  2. En su lugar, el sistema incluye en la respuesta la recomendación de contención.
  3. En la interfaz Streamlit, se resalta una tarjeta:  
     `"⚠️ Jev recomienda aislar el host SRV-FINANCE-02 (probabilidad 92%). [Simular Acción]"`
  4. El analista pulsa el botón y se emite `POST /v1/incidents/{id}/containment/simulate` con `mode="simulation"`.

---

## 4. Salvaguardas y Requisitos Operativos (Guardrails)

1. **Aislamiento de Telemetría Oficial vs Sintética (`AGENTS.md`)**:
   - Si `dataset_kind == "synthetic"`: Se permite pasar a Jev el contexto del proceso, host y usuario.
   - Si `dataset_kind == "official"`: **No sale ningún payload fuera del entorno local**. Se bifurca obligatoriamente al `DeterministicTriageEngine`.
2. **Resiliencia y Fallback Determinista**:
   - `typesafe-sdk` debe ser una dependencia opcional importada condicionalmente (`try: ... except ImportError:`).
   - Ante fallos de red, cuota, timeout (>3.0s) o respuestas anómalas, se genera el triage determinista sin interrumpir la experiencia de usuario.
3. **Reproducibilidad y fijación de versión**:
   - Usar `jev-1.13.0` como versión fija por defecto, configurable mediante variable de entorno `GSEC_JEV_MODEL`.

---

## 5. Cambios Propuestos por Capas

| Componente | Archivo(s) | Modificación propuesta |
| :--- | :--- | :--- |
| **Dependencias** | `pyproject.toml` | Añadir grupo opcional: `[project.optional-dependencies] jev = ["typesafe-sdk>=0.1.0"]` |
| **Lógica AI** | `backend/ai/__init__.py` | Implementar `TypeSafeJevEngine` con `Choice`, `Score` y `Noul`, manteniendo `DeterministicTriageEngine`. |
| **Utilidades** | `scripts/verify_jev.py` | Script de diagnóstico para comprobar API key, latencia y versión del modelo antes de arrancar. |
| **Consola** | `frontend/app.py` | Mostrar estado de Jev en barra lateral y pre-rellenar formulario de simulación si `aislar.noul >= 0.85`. |
| **Pruebas** | `tests/test_ai.py` | Actualizar mocks para emular las clases `Choice`, `Score`, `Noul` y la estructura `response.answers`. |

---

## 6. Puntos a Debatir Conjuntamente (Usuario + Antigravity + Codex)

1. **Granularidad del `state`**:
   - ¿Enviamos un resumen del evento detonante más crítico del incidente, o un agregado consolidado de todas las alertas que componen el incidente?
2. **Ajuste de umbrales para el hackathon**:
   - Calibrar si `score >= 2.0` es el corte idóneo para clasificar como `likely_true_positive` en el dataset de 30 días de la demo.
3. **Estrategia de asignación de roles entre subagentes de Codex**:
   - `soc_ai`: Encargado de adaptar `backend/ai/__init__.py` y tests correspondientes.
   - `soc_ui`: Encargado de reflejar las probabilidades en la consola Streamlit.
   - `soc_reviewer`: Auditoría final de permisos y cumplimiento de contratos.
