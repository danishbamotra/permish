import subprocess
import pytest

try:
    import psycopg
except ImportError:
    psycopg = None

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "integration" / "docker-compose.yml"


def docker_compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="session", autouse=True)
def postgres_container():
    if psycopg is None:
        pytest.fail("PostgreSQL integration dependency is missing; install permish[postgres]")

    try:
        docker_compose("up", "-d", "--wait")
    except subprocess.CalledProcessError as exc:
        pytest.fail(f"Could not start disposable PostgreSQL: {exc.stderr.strip()}")

    yield

    docker_compose("down", "-v", "--remove-orphans")


@pytest.fixture(scope="session")
def admin_connection(postgres_container):
    with psycopg.connect(
        host="127.0.0.1",
        port=54329,
        dbname="permish_test",
        user="permish_admin",
        password="permish-admin-password",
    ) as connection:
        yield connection


def tenant_connection(role: str, password: str):
    return psycopg.connect(
        host="127.0.0.1",
        port=54329,
        dbname="permish_test",
        user=role,
        password=password,
        autocommit=True,
    )


@pytest.fixture
def tenant_a_connection(postgres_container):
    connection = tenant_connection("permish_tenant_a", "permish-tenant-a-password")
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def tenant_b_connection(postgres_container):
    connection = tenant_connection("permish_tenant_b", "permish-tenant-b-password")
    try:
        yield connection
    finally:
        connection.close()


SAFE_RLS_SQL = """
DO $$
DECLARE policy_name text;
BEGIN
    FOR policy_name IN
        SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = 'private_records'
    LOOP
        EXECUTE format('DROP POLICY %I ON private_records', policy_name);
    END LOOP;
END $$;
ALTER TABLE private_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE private_records FORCE ROW LEVEL SECURITY;
CREATE POLICY private_records_select ON private_records FOR SELECT USING (tenant_id = current_tenant_id());
CREATE POLICY private_records_insert ON private_records FOR INSERT WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY private_records_update ON private_records FOR UPDATE USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());
CREATE POLICY private_records_delete ON private_records FOR DELETE USING (tenant_id = current_tenant_id());
"""


@pytest.fixture(autouse=True)
def reset_database(admin_connection):
    with admin_connection.cursor() as cursor:
        cursor.execute(SAFE_RLS_SQL)
        cursor.execute("TRUNCATE TABLE private_records")
        cursor.execute(
            "INSERT INTO private_records (record_id, tenant_id, payload) VALUES "
            "('record-a', 'tenant-a', 'private-a'), ('record-b', 'tenant-b', 'private-b')"
        )
    admin_connection.commit()
