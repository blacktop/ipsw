-- Enable Row Level Security on all tables
ALTER TABLE ipsws ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipsw_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;

-- Create read-only policies for anonymous users
-- These policies allow SELECT operations for the 'anon' role

-- IPSWs table: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on ipsws" ON ipsws
    FOR SELECT
    TO anon
    USING (true);

-- Devices table: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on devices" ON devices
    FOR SELECT
    TO anon
    USING (true);

-- IPSW-Devices many-to-many: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on ipsw_devices" ON ipsw_devices
    FOR SELECT
    TO anon
    USING (true);

-- Entitlement keys: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_keys" ON entitlement_keys
    FOR SELECT
    TO anon
    USING (true);

-- Entitlement values: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_values" ON entitlement_values
    FOR SELECT
    TO anon
    USING (true);

-- Paths (reused from main IPSW schema): Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on paths" ON paths
    FOR SELECT
    TO anon
    USING (true);

-- Entitlements (main table): Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlements" ON entitlements
    FOR SELECT
    TO anon
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