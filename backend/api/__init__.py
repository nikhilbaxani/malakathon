"""FastAPI integration is implemented in phase 2."""
"""FastAPI application and injectable app factory."""

from backend.api.app import app, create_app

__all__ = ["app", "create_app"]
