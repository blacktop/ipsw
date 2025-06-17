-- Enable Row Level Security on all tables
ALTER TABLE ipsws ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_unique_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_unique_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_unique_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_keys ENABLE ROW LEVEL SECURITY;

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

-- Entitlement unique keys: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_unique_keys" ON entitlement_unique_keys
    FOR SELECT
    TO anon
    USING (true);

-- Entitlement unique values: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_unique_values" ON entitlement_unique_values
    FOR SELECT
    TO anon
    USING (true);

-- Entitlement unique paths: Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_unique_paths" ON entitlement_unique_paths
    FOR SELECT
    TO anon
    USING (true);

-- Entitlement keys (main table): Allow anonymous users to read all records
CREATE POLICY "Allow anonymous read access on entitlement_keys" ON entitlement_keys
    FOR SELECT
    TO anon
    USING (true);

-- Explicitly deny INSERT, UPDATE, DELETE for anonymous users
-- Note: When RLS is enabled and no policy exists for an operation, it's denied by default
-- These policies make the denial explicit for clarity

-- No INSERT policies for anon role means INSERT is denied
-- No UPDATE policies for anon role means UPDATE is denied  
-- No DELETE policies for anon role means DELETE is denied

-- Optional: If you want to be extra explicit, you can create denial policies
-- But this is not necessary as the absence of a policy denies access by default