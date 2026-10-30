from permish import (
    PermissionEngine,
    Principal,
    PrivateResource,
    SafeTenantPolicy,
    VulnerableTenantPolicy,
)


def fixtures():
    principals = (
        Principal("alice", "tenant-a"),
        Principal("bob", "tenant-b"),
    )
    resources = (
        PrivateResource("invoice-a", "tenant-a"),
        PrivateResource("invoice-b", "tenant-b"),
    )
    return principals, resources


class AlwaysAllowPolicy:
    """A deliberately permissive policy used to verify the engine's real decisions."""

    def can_read(self, principal: Principal, resource: PrivateResource) -> bool:
        return True


def test_safe_policy_denies_all_cross_tenant_access():
    principals, resources = fixtures()

    report = PermissionEngine().run(SafeTenantPolicy(), principals, resources)

    assert report.passed
    assert report.findings == ()
    assert len(report.results) == 2


def test_vulnerable_policy_finds_cross_tenant_access_violation():
    principals, resources = fixtures()

    report = PermissionEngine().run(VulnerableTenantPolicy(), principals, resources)

    assert not report.passed
    assert len(report.findings) == 2
    assert {finding.principal.principal_id for finding in report.findings} == {"alice", "bob"}


def test_same_tenant_reads_are_allowed_by_safe_policy():
    principals, resources = fixtures()

    report = PermissionEngine().run(
        SafeTenantPolicy(),
        principals,
        resources,
        cross_tenant_cases_only=False,
    )

    allowed = [
        result
        for result in report.results
        if result.expected_allowed and result.actual_allowed
    ]
    assert report.passed
    assert len(allowed) == 2


def test_cross_tenant_reads_are_denied_by_safe_policy():
    principals, resources = fixtures()

    report = PermissionEngine().run(SafeTenantPolicy(), principals, resources)

    denied = [result for result in report.results if not result.actual_allowed]
    assert report.passed
    assert len(denied) == 2


def test_unknown_user_is_denied_even_when_policy_always_allows():
    principals, resources = fixtures()
    unknown_user = Principal("mallory", "tenant-a")

    allowed = PermissionEngine().authorize(
        AlwaysAllowPolicy(),
        unknown_user,
        resources[0],
        known_principals=principals,
        known_resources=resources,
    )

    assert allowed is False


def test_unknown_resource_is_denied_even_when_policy_always_allows():
    principals, resources = fixtures()
    unknown_resource = PrivateResource("secret-unregistered", "tenant-b")

    allowed = PermissionEngine().authorize(
        AlwaysAllowPolicy(),
        principals[1],
        unknown_resource,
        known_principals=principals,
        known_resources=resources,
    )

    assert allowed is False


def test_policy_exception_fails_closed():
    principals, resources = fixtures()

    class BrokenPolicy:
        def can_read(self, principal: Principal, resource: PrivateResource) -> bool:
            raise RuntimeError("authorization service failure")

    allowed = PermissionEngine().authorize(
        BrokenPolicy(),
        principals[0],
        resources[0],
        known_principals=principals,
        known_resources=resources,
    )

    assert allowed is False
