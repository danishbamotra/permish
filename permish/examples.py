"""Reference policies used to demonstrate expected and vulnerable behavior."""

from .engine import Principal, PrivateResource


class SafeTenantPolicy:
    """A private resource is readable only within its owning tenant."""

    def can_read(self, principal: Principal, resource: PrivateResource) -> bool:
        return principal.tenant_id == resource.tenant_id


class VulnerableTenantPolicy:
    """Intentionally vulnerable example: private resources ignore tenant scope."""

    def can_read(self, principal: Principal, resource: PrivateResource) -> bool:
        return True
