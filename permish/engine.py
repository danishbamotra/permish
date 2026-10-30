"""Deterministic authorization regression testing primitives."""

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    tenant_id: str


@dataclass(frozen=True, slots=True)
class PrivateResource:
    resource_id: str
    tenant_id: str


class PermissionPolicy(Protocol):
    def can_read(self, principal: Principal, resource: PrivateResource) -> bool:
        """Return whether the principal may read the private resource."""


@dataclass(frozen=True, slots=True)
class TestResult:
    principal: Principal
    resource: PrivateResource
    expected_allowed: bool
    actual_allowed: bool

    @property
    def passed(self) -> bool:
        return self.expected_allowed == self.actual_allowed


@dataclass(frozen=True, slots=True)
class Finding:
    principal: Principal
    resource: PrivateResource


@dataclass(frozen=True, slots=True)
class TestReport:
    results: tuple[TestResult, ...]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(
            Finding(result.principal, result.resource)
            for result in self.results
            if not result.passed
        )


class PermissionEngine:
    """Run explicit authorization expectations without external side effects."""

    def authorize(
        self,
        policy: PermissionPolicy,
        principal: Principal,
        resource: PrivateResource,
        known_principals: Sequence[Principal],
        known_resources: Sequence[PrivateResource],
    ) -> bool:
        """Authorize only identities and resources explicitly supplied by the caller."""
        if principal not in known_principals or resource not in known_resources:
            return False

        try:
            return bool(policy.can_read(principal, resource))
        except Exception:
            return False

    def run(
        self,
        policy: PermissionPolicy,
        principals: Sequence[Principal],
        resources: Sequence[PrivateResource],
        cross_tenant_cases_only: bool = True,
    ) -> TestReport:
        results: list[TestResult] = []

        for principal in principals:
            for resource in resources:
                if cross_tenant_cases_only and principal.tenant_id == resource.tenant_id:
                    continue

                expected_allowed = principal.tenant_id == resource.tenant_id
                actual_allowed = self.authorize(
                    policy,
                    principal,
                    resource,
                    known_principals=principals,
                    known_resources=resources,
                )
                results.append(
                    TestResult(
                        principal=principal,
                        resource=resource,
                        expected_allowed=expected_allowed,
                        actual_allowed=actual_allowed,
                    )
                )

        return TestReport(results=tuple(results))
