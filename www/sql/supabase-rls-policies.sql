-- Enable Row Level Security on all tables
ALTER TABLE ipsws ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipsw_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;

-- Browser roles are read-only. Writes are reserved for direct DB credentials used by automation.
REVOKE ALL ON TABLE ipsws, devices, ipsw_devices, entitlement_keys, entitlement_values, paths, entitlements FROM anon, authenticated;
GRANT SELECT ON TABLE ipsws, devices, ipsw_devices, entitlement_keys, entitlement_values, paths, entitlements TO anon, authenticated;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE schemaname = 'public' AND matviewname = 'entitlements_search') THEN
        REVOKE ALL ON TABLE entitlements_search FROM anon, authenticated;
        GRANT SELECT ON TABLE entitlements_search TO anon, authenticated;
    END IF;

    IF to_regprocedure('public.refresh_search_view()') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION refresh_search_view() FROM PUBLIC, anon, authenticated;
    END IF;
END $$;

REVOKE ALL ON SEQUENCE entitlement_keys_id_seq, entitlement_values_id_seq, paths_id_seq, entitlements_id_seq FROM anon, authenticated;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE USAGE, SELECT, UPDATE ON SEQUENCES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon, authenticated;

-- Recreate public read policies idempotently.
DROP POLICY IF EXISTS "Allow public read access" ON ipsws;
DROP POLICY IF EXISTS "Allow public read access" ON devices;
DROP POLICY IF EXISTS "Allow public read access" ON ipsw_devices;
DROP POLICY IF EXISTS "Allow public read access" ON entitlement_keys;
DROP POLICY IF EXISTS "Allow public read access" ON entitlement_values;
DROP POLICY IF EXISTS "Allow public read access" ON paths;
DROP POLICY IF EXISTS "Allow public read access" ON entitlements;
DROP POLICY IF EXISTS "Allow anonymous read access on ipsws" ON ipsws;
DROP POLICY IF EXISTS "Allow anonymous read access on devices" ON devices;
DROP POLICY IF EXISTS "Allow anonymous read access on ipsw_devices" ON ipsw_devices;
DROP POLICY IF EXISTS "Allow anonymous read access on entitlement_keys" ON entitlement_keys;
DROP POLICY IF EXISTS "Allow anonymous read access on entitlement_values" ON entitlement_values;
DROP POLICY IF EXISTS "Allow anonymous read access on paths" ON paths;
DROP POLICY IF EXISTS "Allow anonymous read access on entitlements" ON entitlements;

-- Create read-only policies for browser roles
-- These policies allow SELECT operations for the 'anon' and 'authenticated' roles

-- IPSWs table: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on ipsws" ON ipsws
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- Devices table: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on devices" ON devices
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- IPSW-Devices many-to-many: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on ipsw_devices" ON ipsw_devices
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- Entitlement keys: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_keys" ON entitlement_keys
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- Entitlement values: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_values" ON entitlement_values
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- Paths (reused from main IPSW schema): Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on paths" ON paths
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- Entitlements (main table): Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlements" ON entitlements
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- Grant access to materialized view for fast searches (if it exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'entitlements_search') THEN
        GRANT SELECT ON entitlements_search TO anon, authenticated;
    ELSE
        RAISE NOTICE 'Materialized view entitlements_search does not exist - skipping grant';
    END IF;
END $$;

-- Explicitly deny INSERT, UPDATE, DELETE for anonymous users
-- Note: When RLS is enabled and no policy exists for an operation, it's denied by default
-- These policies make the denial explicit for clarity

-- No INSERT policies for anon role means INSERT is denied
-- No UPDATE policies for anon role means UPDATE is denied  
-- No DELETE policies for anon role means DELETE is denied

-- Optional: If you want to be extra explicit, you can create denial policies
-- But this is not necessary as the absence of a policy denies access by default
