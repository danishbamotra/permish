-- LOCAL DISPOSABLE INTEGRATION TESTING ONLY.
-- These credentials must never be used in production.
CREATE TABLE tenants (
    tenant_id text PRIMARY KEY
);

CREATE TABLE tenant_users (
    role_name text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(tenant_id)
);

CREATE TABLE private_records (
    record_id text PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(tenant_id),
    payload text NOT NULL
);

INSERT INTO tenants (tenant_id) VALUES ('tenant-a'), ('tenant-b');

CREATE ROLE permish_tenant_a LOGIN PASSWORD 'permish-tenant-a-password';
CREATE ROLE permish_tenant_b LOGIN PASSWORD 'permish-tenant-b-password';

INSERT INTO tenant_users (role_name, tenant_id) VALUES
    ('permish_tenant_a', 'tenant-a'),
    ('permish_tenant_b', 'tenant-b');

CREATE FUNCTION current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT tenant_id
    FROM tenant_users
    WHERE role_name = session_user
$$;

ALTER TABLE private_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE private_records FORCE ROW LEVEL SECURITY;

CREATE POLICY private_records_select ON private_records
    FOR SELECT
    USING (tenant_id = current_tenant_id());

CREATE POLICY private_records_insert ON private_records
    FOR INSERT
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY private_records_update ON private_records
    FOR UPDATE
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

CREATE POLICY private_records_delete ON private_records
    FOR DELETE
    USING (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON private_records TO permish_tenant_a, permish_tenant_b;
GRANT EXECUTE ON FUNCTION current_tenant_id() TO permish_tenant_a, permish_tenant_b;

INSERT INTO private_records (record_id, tenant_id, payload) VALUES
    ('record-a', 'tenant-a', 'private-a'),
    ('record-b', 'tenant-b', 'private-b');
