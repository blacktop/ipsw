-- Clear all entitlement data from Supabase tables
-- This script safely removes all data while preserving table structure
-- Run this before re-indexing an IPSW from scratch

-- Disable triggers and constraints temporarily for faster deletion
SET session_replication_role = replica;

-- Clear data in dependency order (child tables first, then parent tables)

-- 1. Clear the main entitlements mapping table first
TRUNCATE TABLE entitlements CASCADE;

-- 2. Clear the IPSW-device relationships
TRUNCATE TABLE ipsw_devices CASCADE;

-- 3. Clear the lookup tables
TRUNCATE TABLE entitlement_keys CASCADE;
TRUNCATE TABLE entitlement_values CASCADE;
TRUNCATE TABLE paths CASCADE;

-- 4. Clear devices (will be recreated when indexing)
TRUNCATE TABLE devices CASCADE;

-- 5. Clear IPSWs last (parent table)
TRUNCATE TABLE ipsws CASCADE;

-- Re-enable triggers and constraints
SET session_replication_role = DEFAULT;

-- Refresh the materialized view if it exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'entitlements_search') THEN
        REFRESH MATERIALIZED VIEW entitlements_search;
    ELSE
        RAISE NOTICE 'Materialized view entitlements_search does not exist - skipping refresh';
    END IF;
END $$;

-- Reset sequences to start from 1 (optional, for clean IDs)
-- Note: Only reset sequences that exist
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_sequences WHERE sequencename = 'entitlement_keys_id_seq') THEN
        ALTER SEQUENCE entitlement_keys_id_seq RESTART WITH 1;
    END IF;
    
    IF EXISTS (SELECT 1 FROM pg_sequences WHERE sequencename = 'entitlement_values_id_seq') THEN
        ALTER SEQUENCE entitlement_values_id_seq RESTART WITH 1;
    END IF;
    
    IF EXISTS (SELECT 1 FROM pg_sequences WHERE sequencename = 'paths_id_seq') THEN
        ALTER SEQUENCE paths_id_seq RESTART WITH 1;
    END IF;
    
    IF EXISTS (SELECT 1 FROM pg_sequences WHERE sequencename = 'entitlements_id_seq') THEN
        ALTER SEQUENCE entitlements_id_seq RESTART WITH 1;
    END IF;
END $$;

-- Note: VACUUM commands removed as they cannot run in transaction blocks
-- TRUNCATE CASCADE already efficiently reclaims space

-- Display confirmation
SELECT 
    'entitlements' as table_name, 
    COUNT(*) as row_count 
FROM entitlements
UNION ALL
SELECT 
    'entitlement_keys' as table_name, 
    COUNT(*) as row_count 
FROM entitlement_keys
UNION ALL
SELECT 
    'entitlement_values' as table_name, 
    COUNT(*) as row_count 
FROM entitlement_values
UNION ALL
SELECT 
    'paths' as table_name, 
    COUNT(*) as row_count 
FROM paths
UNION ALL
SELECT 
    'ipsws' as table_name, 
    COUNT(*) as row_count 
FROM ipsws
UNION ALL
SELECT 
    'devices' as table_name, 
    COUNT(*) as row_count 
FROM devices
ORDER BY table_name;