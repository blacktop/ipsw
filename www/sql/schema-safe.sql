-- Safe PostgreSQL schema for entitlements database
-- This version checks for existing objects before creating them
-- Run this if you already have some tables created

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For fast text searches

-- Create IPSW table if not exists (matches main IPSW schema)
CREATE TABLE IF NOT EXISTS ipsws (
    id TEXT PRIMARY KEY,
    name TEXT,
    version TEXT,
    buildid TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create devices table if not exists (matches main IPSW schema)
CREATE TABLE IF NOT EXISTS devices (
    name TEXT PRIMARY KEY
);

-- Create ipsw_devices many-to-many table if not exists (matches main IPSW schema)
CREATE TABLE IF NOT EXISTS ipsw_devices (
    ipsw_id TEXT NOT NULL REFERENCES ipsws(id),
    device_name TEXT NOT NULL REFERENCES devices(name),
    PRIMARY KEY(ipsw_id, device_name)
);

-- Entitlement keys table - preserves complete key text
CREATE TABLE IF NOT EXISTS entitlement_keys (
    id SERIAL PRIMARY KEY,
    key TEXT NOT NULL UNIQUE -- CRITICAL: Keep as TEXT - keys must be complete/accurate
);

-- Entitlement values table with optimized hash - preserves complete value text  
CREATE TABLE IF NOT EXISTS entitlement_values (
    id SERIAL PRIMARY KEY,
    value TEXT NOT NULL,     -- CRITICAL: Keep as TEXT - values must be complete/accurate
    value_type VARCHAR(10) NOT NULL CHECK (value_type IN ('bool', 'string', 'array', 'dict', 'number')),
    value_hash CHAR(16) NOT NULL UNIQUE -- Shortened hash for uniqueness (99.999% collision safety)
);

-- Reuse existing paths table from main IPSW schema for consistency
CREATE TABLE IF NOT EXISTS paths (
    id SERIAL PRIMARY KEY,
    path TEXT NOT NULL UNIQUE -- CRITICAL: Keep as TEXT - paths must be complete/accurate
);

-- Main entitlements table (significantly reduced size through normalization)
CREATE TABLE IF NOT EXISTS entitlements (
    id BIGSERIAL PRIMARY KEY, -- Keep as BIGINT for large datasets
    ipsw_id TEXT NOT NULL REFERENCES ipsws(id),
    path_id INTEGER NOT NULL REFERENCES paths(id),
    key_id INTEGER NOT NULL REFERENCES entitlement_keys(id),
    value_id INTEGER NOT NULL REFERENCES entitlement_values(id),
    
    -- Unique constraint to prevent duplicates (fixes original duplicate issue)
    UNIQUE(ipsw_id, path_id, key_id, value_id)
);

-- Create indexes if they don't exist
DO $$
BEGIN
    -- For IPSW version lookups
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_ipsws_version') THEN
        CREATE INDEX idx_ipsws_version ON ipsws(version);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_ipsws_buildid') THEN
        CREATE INDEX idx_ipsws_buildid ON ipsws(buildid);
    END IF;
    
    -- For key pattern searches (GIN index for fast ILIKE)
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_keys_search') THEN
        CREATE INDEX idx_keys_search ON entitlement_keys USING gin(key gin_trgm_ops);
    END IF;
    
    -- For path pattern searches (GIN index for fast ILIKE)  
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_paths_search') THEN
        CREATE INDEX idx_paths_search ON paths USING gin(path gin_trgm_ops);
    END IF;
    
    -- For main table lookups (composite indexes for common query patterns)
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_entitlement_ipsw_key') THEN
        CREATE INDEX idx_entitlement_ipsw_key ON entitlements(ipsw_id, key_id);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_entitlement_ipsw_path') THEN
        CREATE INDEX idx_entitlement_ipsw_path ON entitlements(ipsw_id, path_id);
    END IF;
END $$;

-- Drop materialized view if it exists (we'll recreate it)
DROP MATERIALIZED VIEW IF EXISTS entitlements_search CASCADE;

-- Materialized view for ultra-fast searches (refreshed periodically, not per-query)
CREATE MATERIALIZED VIEW entitlements_search AS
SELECT 
    ek.id,
    i.version as ios_version,
    i.buildid as build_id,
    array_agg(DISTINCT d.name ORDER BY d.name) as device_list,
    up.path as file_path,
    uk.key,
    uv.value_type,
    CASE 
        WHEN uv.value_type = 'string' THEN uv.value
        ELSE NULL
    END as string_value,
    CASE 
        WHEN uv.value_type = 'bool' THEN CASE WHEN uv.value = 'true' THEN true ELSE false END
        ELSE NULL
    END as bool_value,
    CASE 
        WHEN uv.value_type = 'number' THEN uv.value::NUMERIC
        ELSE NULL
    END as number_value,
    CASE 
        WHEN uv.value_type = 'array' THEN uv.value
        ELSE NULL
    END as array_value,
    CASE 
        WHEN uv.value_type = 'dict' THEN uv.value
        ELSE NULL
    END as dict_value,
    i.created_at as release_date
FROM entitlements ek
JOIN ipsws i ON i.id = ek.ipsw_id
JOIN entitlement_keys uk ON uk.id = ek.key_id
JOIN entitlement_values uv ON uv.id = ek.value_id
JOIN paths up ON up.id = ek.path_id
LEFT JOIN ipsw_devices id ON id.ipsw_id = ek.ipsw_id
LEFT JOIN devices d ON d.name = id.device_name
GROUP BY ek.id, i.version, i.buildid, up.path, uk.key, uv.value_type, uv.value, i.created_at;

-- Create indexes on materialized view if they don't exist
DO $$
BEGIN
    -- Indexes on materialized view for lightning-fast searches
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_search_key') THEN
        CREATE INDEX idx_search_key ON entitlements_search USING gin(key gin_trgm_ops);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_search_path') THEN
        CREATE INDEX idx_search_path ON entitlements_search USING gin(file_path gin_trgm_ops);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_search_version') THEN
        CREATE INDEX idx_search_version ON entitlements_search(ios_version);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_search_id') THEN
        CREATE INDEX idx_search_id ON entitlements_search(id); -- For pagination
    END IF;
END $$;

-- Function to refresh materialized view (call periodically, not per-query)
CREATE OR REPLACE FUNCTION refresh_search_view()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY entitlements_search;
END;
$$ LANGUAGE plpgsql;

-- Enable Row Level Security for all tables
ALTER TABLE ipsws ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipsw_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist and recreate them
DO $$
BEGIN
    -- Drop existing policies
    DROP POLICY IF EXISTS "Allow public read access" ON ipsws;
    DROP POLICY IF EXISTS "Allow public read access" ON devices;
    DROP POLICY IF EXISTS "Allow public read access" ON ipsw_devices;
    DROP POLICY IF EXISTS "Allow public read access" ON entitlement_keys;
    DROP POLICY IF EXISTS "Allow public read access" ON entitlement_values;
    DROP POLICY IF EXISTS "Allow public read access" ON paths;
    DROP POLICY IF EXISTS "Allow public read access" ON entitlements;
END $$;

-- Create policies for public read-only access (safe for community service)
CREATE POLICY "Allow public read access" ON ipsws FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON devices FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON ipsw_devices FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON entitlement_keys FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON entitlement_values FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON paths FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON entitlements FOR SELECT USING (true);

-- Grant access to materialized view
GRANT SELECT ON entitlements_search TO anon, authenticated;

-- Analyze all tables for optimal query planning
ANALYZE ipsws;
ANALYZE devices;
ANALYZE ipsw_devices;
ANALYZE entitlement_keys;
ANALYZE entitlement_values;
ANALYZE paths;
ANALYZE entitlements;

-- Display table information
SELECT 
    table_name,
    pg_size_pretty(pg_total_relation_size(table_schema||'.'||table_name)) as size
FROM information_schema.tables
WHERE table_schema = 'public' 
    AND table_name IN ('ipsws', 'devices', 'ipsw_devices', 'entitlement_keys', 'entitlement_values', 'paths', 'entitlements')
ORDER BY table_name;