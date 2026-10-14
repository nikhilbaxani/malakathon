# Triaje

`DeterministicTriageEngine().triage(incident, alerts=..., evidence=..., generated_at=...)`
es la opción local por defecto. Exige que los IDs de alertas y eventos estén
resueltos en la misma partición, conserva los IDs de evidencia y devuelve
`assessment="needs_review"`: una alerta no confirma un ataque.

Jev se habilita expresamente con
`create_triage_engine(enable_jev=True, api_key=clave, timeout=3.0)` y el paquete
opcional `typesafe-sdk`. No se lee una clave del entorno automáticamente ni se
realizan llamadas de red sin esa habilitación. Si falta el SDK, la llamada falla,
el proveedor responde con una categoría inesperada o el incidente pertenece a
un dataset `official`, se utiliza el motor determinista. `engine` refleja el
motor que realmente produjo el resultado.

El adaptador fija el host oficial, desactiva reintentos y usa timeout. Solo
envía a Jev el número de alertas sintéticas y sus conteos por severidad. No
envía eventos, atributos, contenido original, IDs, títulos, descripciones ni
marcas de tiempo. La respuesta de Jev es una **sugerencia de prioridad para
revisión humana**; no se convierte en afirmación de intrusión ni en probabilidad
de que un evento sea cierto.

API y SDK verificados en documentación primaria de TypeSafe:

- https://docs.typesafe.ai/introduction/quickstart
- https://docs.typesafe.ai/sdk/python
- https://github.com/typesafe-ai/typesafe-sdk-python

Las pruebas usan clientes mock y no requieren la clave, el SDK ni conexión:
`.venv/bin/python -m pytest -q tests/test_ai.py`.
