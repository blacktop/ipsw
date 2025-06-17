-- PostgreSQL schema for entitlements database (migrated from SQLite)

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create tables for unique normalized data
CREATE TABLE entitlement_unique_keys (
    id SERIAL PRIMARY KEY,
    key TEXT NOT NULL
);

CREATE TABLE entitlement_unique_values (
    id SERIAL PRIMARY KEY,
    value TEXT NOT NULL,
    value_type TEXT NOT NULL,
    value_hash TEXT NOT NULL
);

CREATE TABLE entitlement_unique_paths (
    id SERIAL PRIMARY KEY,
    path TEXT NOT NULL
);

-- Main entitlements table
CREATE TABLE entitlement_keys (
    id SERIAL PRIMARY KEY,
    ios_version TEXT NOT NULL,
    build_id TEXT NOT NULL,
    device_list TEXT,
    path_id INTEGER NOT NULL REFERENCES entitlement_unique_paths(id),
    key_id INTEGER NOT NULL REFERENCES entitlement_unique_keys(id),
    value_id INTEGER NOT NULL REFERENCES entitlement_unique_values(id),
    release_date TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance (matching SQLite schema)
CREATE UNIQUE INDEX idx_entitlement_unique_keys_key ON entitlement_unique_keys(key);
CREATE UNIQUE INDEX idx_entitlement_unique_values_value_hash ON entitlement_unique_values(value_hash);
CREATE UNIQUE INDEX idx_entitlement_unique_paths_path ON entitlement_unique_paths(path);

CREATE INDEX idx_entitlement_keys_value_id ON entitlement_keys(value_id);
CREATE INDEX idx_version_path ON entitlement_keys(path_id);
CREATE INDEX idx_entitlement_keys_device_list ON entitlement_keys(device_list);
CREATE INDEX idx_entitlement_keys_build_id ON entitlement_keys(build_id);
CREATE INDEX idx_version_key ON entitlement_keys(ios_version, key_id);

-- Enable Row Level Security (optional, can be configured later)
ALTER TABLE entitlement_unique_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_unique_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_unique_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_keys ENABLE ROW LEVEL SECURITY;

-- Create policies for read-only access (public read access for entitlements browser)
CREATE POLICY "Allow public read access" ON entitlement_unique_keys FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON entitlement_unique_values FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON entitlement_unique_paths FOR SELECT USING (true);
CREATE POLICY "Allow public read access" ON entitlement_keys FOR SELECT USING (true);

-- Create a view for easier querying (matches the existing query structure)
CREATE VIEW entitlements_view AS
SELECT 
    ek.id,
    ek.ios_version,
    ek.build_id,
    ek.device_list,
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
    ek.release_date
FROM entitlement_keys ek
JOIN entitlement_unique_keys uk ON uk.id = ek.key_id
JOIN entitlement_unique_values uv ON uv.id = ek.value_id
JOIN entitlement_unique_paths up ON up.id = ek.path_id;

-- Grant access to the view as well
ALTER TABLE entitlements_view OWNER TO postgres;