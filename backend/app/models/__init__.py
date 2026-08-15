"""Importing this package registers every ORM model on `Base.metadata`, which is what
`alembic/env.py` relies on for autogeneration. M1 implements Core only (docs/02) —
events/signals/incidents/etc. land at M3+."""

from __future__ import annotations

from app.models.analysis import Analysis
from app.models.base import (
    MissingTenantScopeError,
    TenantScopedMixin,
    bypass_tenant_scope,
    tenant_scope,
    tenant_session,
)
from app.models.tenant import Tenant
from app.models.upload import Upload
from app.models.user import User

__all__ = [
    "Analysis",
    "MissingTenantScopeError",
    "Tenant",
    "TenantScopedMixin",
    "Upload",
    "User",
    "bypass_tenant_scope",
    "tenant_scope",
    "tenant_session",
]
