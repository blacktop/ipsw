import { createClient } from '@supabase/supabase-js';

// Supabase configuration
const supabaseUrl = process.env.REACT_APP_SUPABASE_URL || 'https://aitihoxmzyhwrzacrzgv.supabase.co';
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFpdGlob3htenlod3J6YWNyemd2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAxMzkwMTQsImV4cCI6MjA2NTcxNTAxNH0.4PLwcxdZiP3XyYUu-FOFAPH1DVbuOo0lQhtYapoqhDk';

// Check if Supabase is configured
const isSupabaseConfigured = !!(supabaseUrl && supabaseAnonKey);

if (!isSupabaseConfigured) {
  console.warn('Supabase configuration missing. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
}

// Create client with dummy values if not configured (to prevent errors)
export const supabase = createClient(
  supabaseUrl || 'https://dummy.supabase.co',
  supabaseAnonKey || 'dummy-key'
);

// Database types matching our schema
export interface EntitlementResult {
  id: number;
  ios_version: string;
  build_id: string;
  device_list: string | null;
  file_path: string;
  key: string;
  value_type: 'string' | 'bool' | 'number' | 'array' | 'dict';
  string_value: string | null;
  bool_value: boolean | null;
  number_value: number | null;
  array_value: string | null;
  dict_value: string | null;
  release_date: string | null;
}

// Helper functions for querying entitlements
export class EntitlementsService {
  /**
   * Check if Supabase is properly configured
   */
  static isConfigured(): boolean {
    return isSupabaseConfigured;
  }

  /**
   * Get all available iOS versions
   */
  static async getIosVersions(): Promise<string[]> {
    if (!isSupabaseConfigured) {
      throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
    }

    // Use the ipsws table which only has 2 records - much more efficient!
    try {
      const { data, error } = await supabase
        .from('ipsws')
        .select('version')
        .order('version', { ascending: false }); // Sort versions descending

      if (error) {
        throw new Error(`Failed to fetch iOS versions: ${error.message}`);
      }

      if (!data || data.length === 0) {
        console.warn('No iOS version data found in ipsws table');
        return [];
      }

      // Extract unique versions and filter out any null/undefined values
      const versions = data.map(row => row.version).filter(Boolean) as string[];

      // Sort versions numerically (e.g., 26.0, 18.5, 18.2, etc.) - just to be sure
      versions.sort((a: string, b: string) => {
        const parseVersion = (version: string) => {
          const parts = version.split('.').map(Number);
          return parts[0] * 1000 + (parts[1] || 0);
        };
        return parseVersion(b) - parseVersion(a); // Descending order
      });

      return versions;

    } catch (error: any) {
      console.error('Error fetching iOS versions from ipsws table:', error);
      throw new Error(`Failed to fetch iOS versions: ${error.message}`);
    }
  }

  /**
   * Search for entitlements by key pattern
   */
  static async searchByKey(
    keyPattern: string,
    iosVersion?: string,
    executablePath?: string,
    limit: number = 200
  ): Promise<EntitlementResult[]> {
    if (!isSupabaseConfigured) {
      throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
    }

    // First, let's try a simpler approach by querying each table separately
    // Get unique keys that match the pattern first
    const { data: matchingKeys, error: keyError } = await supabase
      .from('entitlement_unique_keys')
      .select('id, key')
      .ilike('key', `%${keyPattern}%`);

    if (keyError) {
      throw new Error(`Failed to search keys: ${keyError.message}`);
    }

    if (!matchingKeys || matchingKeys.length === 0) {
      return [];
    }

    // Get the key IDs
    const keyIds = matchingKeys.map(k => k.id);

    // Now query entitlement_keys with those key IDs
    let query = supabase
      .from('entitlement_keys')
      .select(`
        *,
        entitlement_unique_keys!key_id(key),
        entitlement_unique_values!value_id(value, value_type),
        entitlement_unique_paths!path_id(path)
      `)
      .in('key_id', keyIds);

    // Filter by iOS version
    if (iosVersion) {
      query = query.eq('ios_version', iosVersion);
    }

    // Filter by file path through path IDs if needed
    if (executablePath) {
      // First get matching paths
      const { data: matchingPaths } = await supabase
        .from('entitlement_unique_paths')
        .select('id')
        .eq('path', executablePath);

      if (matchingPaths && matchingPaths.length > 0) {
        const pathIds = matchingPaths.map(p => p.id);
        query = query.in('path_id', pathIds);
      } else {
        return []; // No matching paths
      }
    }

    query = query
      .order('path_id')
      .order('key_id')
      .limit(limit);

    const { data, error } = await query;

    if (error) {
      throw new Error(`Failed to search by key: ${error.message}`);
    }

    return this.transformSearchResults(data || []);
  }

  /**
   * Search for entitlements by file path pattern
   */
  static async searchByFile(
    filePattern: string,
    iosVersion?: string,
    executablePath?: string,
    limit: number = 200
  ): Promise<EntitlementResult[]> {
    if (!isSupabaseConfigured) {
      throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
    }

    // Query the entitlement_keys table with joins to get the actual key, value, and path data
    let query = supabase
      .from('entitlement_keys')
      .select(`
        id,
        ios_version,
        build_id,
        device_list,
        path_id,
        key_id,
        value_id,
        release_date,
        entitlement_unique_keys!key_id(key),
        entitlement_unique_values!value_id(value, value_type),
        entitlement_unique_paths!path_id(path)
      `);

    // Filter by iOS version
    if (iosVersion) {
      query = query.eq('ios_version', iosVersion);
    }

    // Filter by executable path through the joined table
    if (executablePath) {
      query = query.eq('entitlement_unique_paths.path', executablePath);
    }

    // Filter by file pattern through the joined table
    query = query.ilike('entitlement_unique_paths.path', `%${filePattern}%`);

    query = query
      .order('path_id')
      .order('key_id')
      .limit(limit);

    const { data, error } = await query;

    if (error) {
      throw new Error(`Failed to search by file: ${error.message}`);
    }

    return this.transformSearchResults(data || []);
  }

  /**
   * Transform search results from the joined query format to the expected EntitlementResult format
   */
  private static transformSearchResults(data: any[]): EntitlementResult[] {
    // Transform the raw data
    const results = data.map(row => ({
      id: row.id,
      ios_version: row.ios_version,
      build_id: row.build_id,
      device_list: row.device_list,
      file_path: row.entitlement_unique_paths?.path || '',
      key: row.entitlement_unique_keys?.key || '',
      value_type: row.entitlement_unique_values?.value_type || 'string',
      string_value: row.entitlement_unique_values?.value_type === 'string' ? row.entitlement_unique_values?.value : null,
      bool_value: row.entitlement_unique_values?.value_type === 'bool' ? (row.entitlement_unique_values?.value === 'true') : null,
      number_value: row.entitlement_unique_values?.value_type === 'number' ? parseFloat(row.entitlement_unique_values?.value || '0') : null,
      array_value: row.entitlement_unique_values?.value_type === 'array' ? row.entitlement_unique_values?.value : null,
      dict_value: row.entitlement_unique_values?.value_type === 'dict' ? row.entitlement_unique_values?.value : null,
      release_date: row.release_date
    }));

    // Deduplicate based on unique combination of ios_version, file_path, key, and value
    const seen = new Set<string>();
    const deduplicated: EntitlementResult[] = [];
    
    for (const result of results) {
      // Create a unique key based on the combination of fields that define uniqueness
      const uniqueKey = `${result.ios_version}|${result.file_path}|${result.key}|${result.value_type}|${result.string_value || result.bool_value || result.number_value || result.array_value || result.dict_value}`;
      
      if (!seen.has(uniqueKey)) {
        seen.add(uniqueKey);
        deduplicated.push(result);
      }
    }
    
    return deduplicated;
  }

  /**
   * Test database connection
   */
  static async testConnection(): Promise<boolean> {
    if (!isSupabaseConfigured) {
      return false;
    }

    try {
      const { data, error, count } = await supabase
        .from('entitlement_unique_keys')
        .select('*', { count: 'exact', head: true })
        .limit(1);

      if (error) {
        return false;
      }

      return true;
    } catch (err) {
      return false;
    }
  }

  /**
   * Get database statistics
   */
  static async getStats(): Promise<{
    totalEntitlements: number;
    uniqueKeys: number;
    uniquePaths: number;
    iosVersions: number;
  }> {
    if (!isSupabaseConfigured) {
      throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
    }

    const [entitlementsCount, keysCount, pathsCount, versionsCount] = await Promise.all([
      supabase.from('entitlement_keys').select('*', { count: 'exact', head: true }),
      supabase.from('entitlement_unique_keys').select('*', { count: 'exact', head: true }),
      supabase.from('entitlement_unique_paths').select('*', { count: 'exact', head: true }),
      supabase.from('entitlement_keys').select('ios_version').then(({ data }) =>
        new Set(data?.map(row => row.ios_version) || []).size
      )
    ]);

    return {
      totalEntitlements: entitlementsCount.count || 0,
      uniqueKeys: keysCount.count || 0,
      uniquePaths: pathsCount.count || 0,
      iosVersions: versionsCount
    };
  }
}