import psycopg
import pytest

from permish.demo import (
    DemoHTTPPermissionPolicy,
    FixedRecordRepository,
    SYNTHETIC_PRINCIPALS,
    VulnerableRecordRepository,
    create_demo_app,
)
from permish.engine import PermissionEngine, PrivateResource

from integration.rls import VULNERABLE_RLS_SQL


pytestmark = pytest.mark.integration


def connection_factory(*, role: str, password: str):
    return psycopg.connect(
        host="127.0.0.1",
        port=54329,
        dbname="permish_test",
        user=role,
        password=password,
        autocommit=True,
    )


def test_fixed_demo_rejects_tenant_a_access_to_tenant_b_record():
    app = create_demo_app(connection_factory, FixedRecordRepository)

    response = app.test_client().get(
        "/records/record-b",
        headers={"X-Permish-Principal": "alice"},
    )

    assert response.status_code == 404

    report = PermissionEngine().run(
        DemoHTTPPermissionPolicy(app),
        principals=(SYNTHETIC_PRINCIPALS["alice"],),
        resources=(PrivateResource("record-b", "tenant-b"),),
    )
    assert report.passed
    assert report.findings == ()


def test_vulnerable_demo_detects_tenant_a_access_to_tenant_b_record(
    admin_connection,
):
    with admin_connection.cursor() as cursor:
        cursor.execute(VULNERABLE_RLS_SQL)
    admin_connection.commit()

    app = create_demo_app(connection_factory, VulnerableRecordRepository)

    response = app.test_client().get(
        "/records/record-b",
        headers={"X-Permish-Principal": "alice"},
    )

    assert response.status_code == 200
    assert response.get_json()["tenant_id"] == "tenant-b"

    report = PermissionEngine().run(
        DemoHTTPPermissionPolicy(app),
        principals=(SYNTHETIC_PRINCIPALS["alice"],),
        resources=(PrivateResource("record-b", "tenant-b"),),
    )
    assert not report.passed
    assert len(report.findings) == 1
    assert report.findings[0].principal.principal_id == "alice"
    assert report.findings[0].resource.resource_id == "record-b"
