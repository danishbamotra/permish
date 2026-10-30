import psycopg
import pytest

from permish import PermissionEngine, Principal, PrivateResource
from permish.postgresql import PostgreSQLPermissionPolicy
from integration.rls import VULNERABLE_RLS_SQL


pytestmark = pytest.mark.integration



def select_ids(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT record_id FROM private_records ORDER BY record_id")
        return [row[0] for row in cursor.fetchall()]


def test_tenant_a_can_read_and_modify_only_its_records(tenant_a_connection):
    assert select_ids(tenant_a_connection) == ["record-a"]

    with tenant_a_connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO private_records (record_id, tenant_id, payload) VALUES (%s, %s, %s)",
            ("record-a-new", "tenant-a", "private-a-new"),
        )
        cursor.execute(
            "UPDATE private_records SET payload = %s WHERE record_id = %s",
            ("updated-a", "record-a-new"),
        )
        assert cursor.rowcount == 1
        cursor.execute("DELETE FROM private_records WHERE record_id = %s", ("record-a-new",))
        assert cursor.rowcount == 1


def test_tenant_b_can_read_and_modify_only_its_records(tenant_b_connection):
    assert select_ids(tenant_b_connection) == ["record-b"]

    with tenant_b_connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO private_records (record_id, tenant_id, payload) VALUES (%s, %s, %s)",
            ("record-b-new", "tenant-b", "private-b-new"),
        )
        cursor.execute(
            "UPDATE private_records SET payload = %s WHERE record_id = %s",
            ("updated-b", "record-b-new"),
        )
        assert cursor.rowcount == 1
        cursor.execute("DELETE FROM private_records WHERE record_id = %s", ("record-b-new",))
        assert cursor.rowcount == 1


def test_tenant_a_cannot_read_or_modify_tenant_b_records(tenant_a_connection):
    with tenant_a_connection.cursor() as cursor:
        cursor.execute("SELECT record_id FROM private_records WHERE record_id = 'record-b'")
        assert cursor.fetchall() == []

        with pytest.raises(psycopg.Error):
            cursor.execute(
                "INSERT INTO private_records (record_id, tenant_id, payload) VALUES ('cross-a', 'tenant-b', 'forbidden')"
            )


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_tenant_a_cannot_modify_tenant_b_records(tenant_a_connection, operation):
    with tenant_a_connection.cursor() as cursor:
        if operation == "update":
            cursor.execute(
                "UPDATE private_records SET payload = 'forbidden' WHERE record_id = 'record-b'"
            )
        else:
            cursor.execute("DELETE FROM private_records WHERE record_id = 'record-b'")
        assert cursor.rowcount == 0


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_tenant_b_cannot_modify_tenant_a_records(tenant_b_connection, operation):
    with tenant_b_connection.cursor() as cursor:
        if operation == "update":
            cursor.execute(
                "UPDATE private_records SET payload = 'forbidden' WHERE record_id = 'record-a'"
            )
        else:
            cursor.execute("DELETE FROM private_records WHERE record_id = 'record-a'")
        assert cursor.rowcount == 0


def test_tenant_b_cannot_insert_tenant_a_record(tenant_b_connection):
    with tenant_b_connection.cursor() as cursor:
        with pytest.raises(psycopg.Error):
            cursor.execute(
                "INSERT INTO private_records (record_id, tenant_id, payload) VALUES ('cross-b', 'tenant-a', 'forbidden')"
            )


def test_vulnerable_rls_configuration_is_detected_by_permish(admin_connection, tenant_a_connection):
    with admin_connection.cursor() as cursor:
        cursor.execute(VULNERABLE_RLS_SQL)
    admin_connection.commit()

    principals = (Principal("alice", "tenant-a"),)
    resources = (PrivateResource("record-b", "tenant-b"),)

    report = PermissionEngine().run(
        PostgreSQLPermissionPolicy(tenant_a_connection),
        principals,
        resources,
    )

    with tenant_a_connection.cursor() as cursor:
        cursor.execute("SELECT record_id FROM private_records WHERE record_id = 'record-b'")
        assert cursor.fetchall() == [("record-b",)]

    assert not report.passed
    assert len(report.findings) == 1
    assert report.findings[0].principal.principal_id == "alice"
    assert report.findings[0].resource.resource_id == "record-b"

    with tenant_a_connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO private_records (record_id, tenant_id, payload) VALUES ('vulnerable-a', 'tenant-b', 'unexpected')"
        )
        cursor.execute(
            "UPDATE private_records SET payload = 'unexpected-update' WHERE record_id = 'record-b'"
        )
        assert cursor.rowcount == 1
        cursor.execute("DELETE FROM private_records WHERE record_id = 'record-b'")
        assert cursor.rowcount == 1
