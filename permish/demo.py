"""Small Flask + PostgreSQL demonstration for disposable integration tests."""

from typing import Callable

import psycopg
from flask import Flask, abort, g, request

from .engine import Principal, PrivateResource


SYNTHETIC_PRINCIPALS = {
    "alice": Principal("alice", "tenant-a"),
    "bob": Principal("bob", "tenant-b"),
}

SYNTHETIC_ROLE_MAP = {
    "tenant-a": ("permish_tenant_a", "permish-tenant-a-password"),
    "tenant-b": ("permish_tenant_b", "permish-tenant-b-password"),
}

ConnectionFactory = Callable[..., psycopg.Connection]


class VulnerableRecordRepository:
    """Deliberately omits tenant ownership from the record lookup."""

    def __init__(self, connection_factory: ConnectionFactory):
        self.connection_factory = connection_factory

    def get_record(self, principal: Principal, record_id: str):
        role, password = SYNTHETIC_ROLE_MAP[principal.tenant_id]
        with self.connection_factory(role=role, password=password) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT record_id, tenant_id, payload FROM private_records "
                    "WHERE record_id = %s",
                    (record_id,),
                )
                return cursor.fetchone()


class FixedRecordRepository:
    """Loads a record only when its tenant_id matches the authenticated principal."""

    def __init__(self, connection_factory: ConnectionFactory):
        self.connection_factory = connection_factory

    def get_record(self, principal: Principal, record_id: str):
        role, password = SYNTHETIC_ROLE_MAP[principal.tenant_id]
        with self.connection_factory(role=role, password=password) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT record_id, tenant_id, payload FROM private_records "
                    "WHERE record_id = %s AND tenant_id = %s",
                    (record_id, principal.tenant_id),
                )
                return cursor.fetchone()


def create_demo_app(
    connection_factory: ConnectionFactory,
    repository_factory,
) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SYNTHETIC_PRINCIPALS"] = SYNTHETIC_PRINCIPALS

    @app.before_request
    def resolve_principal():
        principal_id = request.headers.get("X-Permish-Principal")
        principal = SYNTHETIC_PRINCIPALS.get(principal_id or "")
        if principal is None:
            abort(401, description="Unknown synthetic principal")
        g.principal = principal

    repository = repository_factory(connection_factory)

    @app.get("/records/<record_id>")
    def get_record(record_id: str):
        row = repository.get_record(g.principal, record_id)
        if row is None:
            abort(404, description="Record not found")
        return {
            "record_id": row[0],
            "tenant_id": row[1],
            "payload": row[2],
        }

    return app


class DemoHTTPPermissionPolicy:
    """Permission policy backed by actual Flask test-client observations."""

    def __init__(self, app: Flask):
        self.app = app

    def can_read(self, principal: Principal, resource: PrivateResource) -> bool:
        with self.app.test_client() as client:
            response = client.get(
                f"/records/{resource.resource_id}",
                headers={"X-Permish-Principal": principal.principal_id},
            )
        return 200 <= response.status_code < 300
