"""PostgreSQL permission adapter that observes decisions through RLS."""

from typing import Any

from .engine import Principal, PrivateResource


class PostgreSQLPermissionPolicy:
    """Ask PostgreSQL whether the supplied tenant role can read a resource."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def can_read(self, principal: Principal, resource: PrivateResource) -> bool:
        del principal
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM private_records WHERE record_id = %s)",
                (resource.resource_id,),
            )
            return bool(cursor.fetchone()[0])
