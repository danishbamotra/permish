VULNERABLE_RLS_SQL = """
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
CREATE POLICY private_records_select ON private_records FOR SELECT USING (true);
CREATE POLICY private_records_insert ON private_records FOR INSERT WITH CHECK (true);
CREATE POLICY private_records_update ON private_records FOR UPDATE USING (true) WITH CHECK (true);
CREATE POLICY private_records_delete ON private_records FOR DELETE USING (true);
"""
