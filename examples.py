"""Small local demonstration of a cross-tenant authorization regression."""

from permish import (
    PermissionEngine,
    Principal,
    PrivateResource,
    SafeTenantPolicy,
    VulnerableTenantPolicy,
)


principals = (
    Principal("alice", "tenant-a"),
    Principal("bob", "tenant-b"),
)
resources = (
    PrivateResource("private-a", "tenant-a"),
    PrivateResource("private-b", "tenant-b"),
)
engine = PermissionEngine()

print("Safe policy:")
safe_report = engine.run(SafeTenantPolicy(), principals, resources)
print(f"passed={safe_report.passed} findings={len(safe_report.findings)}")

print("Vulnerable policy (intentional):")
vulnerable_report = engine.run(VulnerableTenantPolicy(), principals, resources)
print(f"passed={vulnerable_report.passed} findings={len(vulnerable_report.findings)}")
for finding in vulnerable_report.findings:
    print(
        f"cross-tenant violation: {finding.principal.principal_id} -> "
        f"{finding.resource.resource_id}"
    )

unknown_user_allowed = engine.authorize(
    VulnerableTenantPolicy(),
    Principal("unknown-user", "tenant-a"),
    resources[0],
    known_principals=principals,
    known_resources=resources,
)
unknown_resource_allowed = engine.authorize(
    VulnerableTenantPolicy(),
    principals[0],
    PrivateResource("unknown-resource", "tenant-a"),
    known_principals=principals,
    known_resources=resources,
)
print(f"unknown user allowed={unknown_user_allowed}")
print(f"unknown resource allowed={unknown_resource_allowed}")
