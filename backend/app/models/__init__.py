"""Importing this package registers every ORM model on `Base.metadata`, which is what
`alembic/env.py` relies on for autogeneration. M1 shipped Core only (docs/02); `events`
(M3, app/models/event.py) is the first table added since. signals/incidents/etc. land
at later milestones."""

from __future__ import annotations

from app.models.analysis import Analysis
from app.models.base import (
    MissingTenantScopeError,
    TenantScopedMixin,
    bypass_tenant_scope,
    tenant_scope,
    tenant_session,
)
from app.models.event import Event
from app.models.tenant import Tenant
from app.models.upload import Upload
from app.models.user import User

__all__ = [
    "Analysis",
    "Event",
    "MissingTenantScopeError",
    "Tenant",
    "TenantScopedMixin",
    "Upload",
    "User",
    "bypass_tenant_scope",
    "tenant_scope",
    "tenant_session",
]
