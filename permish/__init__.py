"""Permish authorization regression testing engine."""

from .engine import (
    Finding,
    PermissionEngine,
    PermissionPolicy,
    Principal,
    PrivateResource,
    TestReport,
    TestResult,
)
from .examples import SafeTenantPolicy, VulnerableTenantPolicy
from .postgresql import PostgreSQLPermissionPolicy

__all__ = [
    "Finding",
    "PermissionEngine",
    "PermissionPolicy",
    "Principal",
    "PrivateResource",
    "TestReport",
    "TestResult",
    "SafeTenantPolicy",
    "VulnerableTenantPolicy",
    "PostgreSQLPermissionPolicy",
]
