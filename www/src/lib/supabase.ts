import { createClient } from '@supabase/supabase-js';

// Define the result type for the optimized schema
export interface EntitlementResult {
  id: number;
  ios_version: string;
  build_id: string;
  device_list: string[] | string; // Array from materialized view, string for compatibility
  file_path: string;
  key: string;
  value_type: string;
  string_value?: string;
  bool_value?: boolean;
  number_value?: number;
  array_value?: string;
  dict_value?: string;
  release_date?: string;
}

// Pagination interface
export interface PaginatedResults {
  results: EntitlementResult[];
  nextCursor?: number;
  hasMore: boolean;
  totalCount?: number;
}

// Environment variables
const supabaseUrl = process.env.REACT_APP_SUPABASE_URL || 'https://qimikoxygfitwklevlcs.supabase.co';
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFpbWlrb3h5Z2ZpdHdrbGV2bGNzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAyODEyODcsImV4cCI6MjA2NTg1NzI4N30.gM_A8GCTRmuz94FKDbtvDDtNQ_ja8bSfp2yW0Lz9U-E';


const isSupabaseConfigured = !!(supabaseUrl && supabaseAnonKey);

let supabase: ReturnType<typeof createClient> | null = null;

if (isSupabaseConfigured) {
  supabase = createClient(supabaseUrl, supabaseAnonKey);
}

// Result cache for improved performance - use union type to handle different data types
const searchCache = new Map<string, { data: EntitlementResult[] | string[], timestamp: number }>();
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes cache

export class EntitlementsService {
  /**
   * Check if Supabase is configured
   */
  static isConfigured(): boolean {
    return isSupabaseConfigured;
  }

  /**
   * Test database connection
   */
  static async testConnection(): Promise<boolean> {
    if (!isSupabaseConfigured || !supabase) {
      return false;
    }

    try {
      // First try to connect to the materialized view
      const { data: viewData, error: viewError } = await supabase
        .from('entitlements_search')
        .select('*', { count: 'exact', head: true })
        .limit(1);

      if (!viewError) {
        return true;
      }

      // If materialized view fails, try base table
      const { data, error } = await supabase
        .from('entitlement_keys')
        .select('*', { count: 'exact', head: true })
        .limit(1);

      return !error;
    } catch (err) {
      console.error('Connection test failed:', err);
      return false;
    }
  }

  /**
   * Optimized search by key pattern using materialized view
   */
  static async searchByKey(
    keyPattern: string,
    iosVersion?: string,
    executablePath?: string,
    limit: number = 50, // Reduced default limit for better performance
    cursor?: number
  ): Promise<EntitlementResult[]> {
    if (!isSupabaseConfigured || !supabase) {
      throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
    }

    // Create cache key
    const cacheKey = `key:${keyPattern}:${iosVersion}:${executablePath}:${limit}:${cursor}`;
    const cached = searchCache.get(cacheKey);

    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      // Type guard to ensure we return EntitlementResult[]
      if (Array.isArray(cached.data) && cached.data.length > 0 && typeof cached.data[0] === 'object') {
        return cached.data as EntitlementResult[];
      }
    }

    // Use base tables with proper filtering approach
    // First, find matching key IDs if we have a key pattern
    let keyIds: number[] = [];
    if (keyPattern) {
      const { data: keyData, error: keyError } = await supabase
        .from('entitlement_keys')
        .select('id, key')
        .ilike('key', `%${keyPattern}%`);

      if (keyError) {
        throw new Error(`Failed to search keys: ${keyError.message}`);
      }

      keyIds = keyData?.map(k => (k.id as number)) || [];

      // If no matching keys found, return empty results
      if (keyIds.length === 0) {
        return [];
      }
    }

    // Build the main query
    let query = supabase
      .from('entitlements')
      .select(`
        id,
        ipsw_id,
        path_id,
        key_id,
        value_id
      `)
      .order('id', { ascending: true })
      .limit(limit);

    // Add cursor for pagination
    if (cursor) {
      query = query.gt('id', cursor);
    }

    // Filter by key IDs if we have a key pattern
    if (keyPattern && keyIds.length > 0) {
      query = query.in('key_id', keyIds);
    }

    // Filter by iOS version - we'll need to get IPSW IDs first
    if (iosVersion) {
      const { data: ipswData } = await supabase
        .from('ipsws')
        .select('id')
        .eq('version', iosVersion);

      const ipswIds = ipswData?.map(i => i.id) || [];
      if (ipswIds.length > 0) {
        query = query.in('ipsw_id', ipswIds);
      } else {
        return []; // No matching iOS version
      }
    }

    // Filter by executable path - we'll need to get path IDs first
    if (executablePath) {
      const { data: pathData } = await supabase
        .from('paths')
        .select('id')
        .eq('path', executablePath);

      const pathIds = pathData?.map(p => (p.id as number)) || [];
      if (pathIds.length > 0) {
        query = query.in('path_id', pathIds);
      } else {
        return []; // No matching path
      }
    }

    const { data, error } = await query;

    if (error) {
      throw new Error(`Failed to search by key: ${error.message}`);
    }

    const results = await this.transformSearchResultsWithLookups(data || []);

    // Cache the results
    searchCache.set(cacheKey, { data: results, timestamp: Date.now() });

    // Clean up old cache entries periodically
    if (searchCache.size > 100) {
      this.cleanupCache();
    }

    return results;
  }

  /**
   * Optimized search by file path pattern using materialized view
   */
  static async searchByFile(
    filePattern: string,
    iosVersion?: string,
    executablePath?: string,
    limit: number = 50,
    cursor?: number
  ): Promise<EntitlementResult[]> {
    if (!isSupabaseConfigured || !supabase) {
      throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
    }

    // Create cache key
    const cacheKey = `file:${filePattern}:${iosVersion}:${executablePath}:${limit}:${cursor}`;
    const cached = searchCache.get(cacheKey);

    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      // Type guard to ensure we return EntitlementResult[]
      if (Array.isArray(cached.data) && cached.data.length > 0 && typeof cached.data[0] === 'object') {
        return cached.data as EntitlementResult[];
      }
    }

    // Use base tables with proper filtering approach
    // First, find matching path IDs if we have a file pattern
    let pathIds: number[] = [];
    if (filePattern || executablePath) {
      const pathQuery = supabase
        .from('paths')
        .select('id');

      if (filePattern) {
        pathQuery.ilike('path', `%${filePattern}%`);
      } else if (executablePath) {
        pathQuery.eq('path', executablePath);
      }

      const { data: pathData, error: pathError } = await pathQuery;

      if (pathError) {
        throw new Error(`Failed to search paths: ${pathError.message}`);
      }

      pathIds = pathData?.map(p => (p.id as number)) || [];

      // If no matching paths found, return empty results
      if (pathIds.length === 0) {
        return [];
      }
    }

    // Build the main query
    let query = supabase
      .from('entitlements')
      .select(`
        id,
        ipsw_id,
        path_id,
        key_id,
        value_id
      `)
      .order('id', { ascending: true })
      .limit(limit);

    // Add cursor for pagination
    if (cursor) {
      query = query.gt('id', cursor);
    }

    // Filter by path IDs if we have a file pattern
    if ((filePattern || executablePath) && pathIds.length > 0) {
      query = query.in('path_id', pathIds);
    }

    // Filter by iOS version - we'll need to get IPSW IDs first
    if (iosVersion) {
      const { data: ipswData } = await supabase
        .from('ipsws')
        .select('id')
        .eq('version', iosVersion);

      const ipswIds = ipswData?.map(i => i.id) || [];
      if (ipswIds.length > 0) {
        query = query.in('ipsw_id', ipswIds);
      } else {
        return []; // No matching iOS version
      }
    }

    const { data, error } = await query;

    if (error) {
      throw new Error(`Failed to search by file: ${error.message}`);
    }

    const results = await this.transformSearchResultsWithLookups(data || []);

    // Cache the results
    searchCache.set(cacheKey, { data: results, timestamp: Date.now() });

    // Clean up old cache entries periodically
    if (searchCache.size > 100) {
      this.cleanupCache();
    }

    return results;
  }

  /**
   * Get unique iOS versions for filter dropdown
   */
  static async getUniqueVersions(): Promise<string[]> {
    if (!isSupabaseConfigured || !supabase) {
      throw new Error('Supabase is not configured.');
    }

    const cacheKey = 'versions';
    const cached = searchCache.get(cacheKey);

    if (cached && Date.now() - cached.timestamp < CACHE_TTL * 6) { // Cache versions longer
      return cached.data as string[];
    }

    const { data, error } = await supabase
      .from('ipsws')
      .select('version')
      .order('version', { ascending: false });

    if (error) {
      throw new Error(`Failed to get versions: ${error.message}`);
    }

    const versions = Array.from(new Set(data?.map(v => v.version).filter((version): version is string => typeof version === 'string') || []));
    searchCache.set(cacheKey, { data: versions, timestamp: Date.now() });

    return versions;
  }

  /**
   * Alias for getUniqueVersions for backward compatibility
   */
  static async getIosVersions(): Promise<string[]> {
    return this.getUniqueVersions();
  }

  /**
   * Transform search results with separate lookups for related data
   * Includes deduplication logic to fix duplicate entries issue
   * 
   * Note: This approach uses separate lookups instead of joins to avoid Supabase
   * relationship schema issues. For large result sets, consider using the 
   * materialized view (entitlements_search) for better performance.
   */
  private static async transformSearchResultsWithLookups(data: any[]): Promise<EntitlementResult[]> {
    if (!supabase || data.length === 0) {
      return [];
    }

    // Extract unique IDs for batch lookups
    const ipswIds = [...new Set(data.map(row => row.ipsw_id))];
    const pathIds = [...new Set(data.map(row => row.path_id))];
    const keyIds = [...new Set(data.map(row => row.key_id))];
    const valueIds = [...new Set(data.map(row => row.value_id))];

    // Batch fetch all related data
    const [ipswData, pathData, keyData, valueData] = await Promise.all([
      supabase.from('ipsws').select('id, version, buildid').in('id', ipswIds),
      supabase.from('paths').select('id, path').in('id', pathIds),
      supabase.from('entitlement_keys').select('id, key').in('id', keyIds),
      supabase.from('entitlement_values').select('id, value, value_type').in('id', valueIds)
    ]);

    // Create lookup maps
    const ipswMap = new Map(ipswData.data?.map(i => [i.id, i]) || []);
    const pathMap = new Map(pathData.data?.map(p => [p.id, p]) || []);
    const keyMap = new Map(keyData.data?.map(k => [k.id, k]) || []);
    const valueMap = new Map(valueData.data?.map(v => [v.id, v]) || []);

    // Transform the raw data
    const results = data.map(row => {
      const ipsw = ipswMap.get(row.ipsw_id);
      const path = pathMap.get(row.path_id);
      const key = keyMap.get(row.key_id);
      const value = valueMap.get(row.value_id);

      return {
        id: row.id as number,
        ios_version: (ipsw?.version as string) || '',
        build_id: (ipsw?.buildid as string) || '',
        device_list: '', // Would need separate device query
        file_path: (path?.path as string) || '',
        key: (key?.key as string) || '',
        value_type: (value?.value_type as string) || 'string',
        string_value: value?.value_type === 'string' ? (value.value as string) : undefined,
        bool_value: value?.value_type === 'bool' ? (value.value === 'true') : undefined,
        number_value: value?.value_type === 'number' && typeof value.value === 'string' ? parseFloat(value.value) : undefined,
        array_value: value?.value_type === 'array' ? (value.value as string) : undefined,
        dict_value: value?.value_type === 'dict' ? (value.value as string) : undefined,
        release_date: undefined
      } as EntitlementResult;
    });

    // Deduplicate based on unique combination of ios_version, file_path, key, and value
    const seen = new Set<string>();
    const deduplicated: EntitlementResult[] = [];

    for (const result of results) {
      // Create a unique key based on the combination of fields that define uniqueness
      const valueStr = result.string_value || result.bool_value || result.number_value || result.array_value || result.dict_value || '';
      const uniqueKey = `${result.ios_version}|${result.file_path}|${result.key}|${result.value_type}|${valueStr}`;

      if (!seen.has(uniqueKey)) {
        seen.add(uniqueKey);
        deduplicated.push(result);
      }
    }

    return deduplicated;
  }

  /**
   * Legacy transform function for backward compatibility
   */
  private static transformSearchResults(data: any[]): EntitlementResult[] {
    // This is for any remaining code that might use the old function
    // We'll return an empty array and log a warning
    console.warn('transformSearchResults called - this should use transformSearchResultsWithLookups');
    return [];
  }

  /**
   * Clean up old cache entries
   */
  private static cleanupCache() {
    const now = Date.now();
    for (const [key, entry] of searchCache.entries()) {
      if (now - entry.timestamp > CACHE_TTL) {
        searchCache.delete(key);
      }
    }
  }

  /**
   * Clear cache manually (useful for testing)
   */
  static clearCache() {
    searchCache.clear();
  }

  /**
   * Get database statistics (optimized)
   */
  static async getStats(): Promise<{
    totalEntitlements: number;
    uniqueKeys: number;
    uniquePaths: number;
    iosVersions: number;
  }> {
    if (!isSupabaseConfigured || !supabase) {
      throw new Error('Supabase is not configured.');
    }

    // Use more efficient count queries
    const [entitlementsCount, keysCount, pathsCount, versionsCount] = await Promise.all([
      supabase.from('entitlements').select('*', { count: 'exact', head: true }),
      supabase.from('entitlement_keys').select('*', { count: 'exact', head: true }),
      supabase.from('paths').select('*', { count: 'exact', head: true }),
      supabase.from('ipsws').select('*', { count: 'exact', head: true })
    ]);

    return {
      totalEntitlements: entitlementsCount.count || 0,
      uniqueKeys: keysCount.count || 0,
      uniquePaths: pathsCount.count || 0,
      iosVersions: versionsCount.count || 0
    };
  }

  /**
   * Refresh materialized view (call this periodically, not per-query)
   */
  static async refreshSearchView(): Promise<void> {
    if (!isSupabaseConfigured || !supabase) {
      throw new Error('Supabase is not configured.');
    }

    const { error } = await supabase.rpc('refresh_search_view');

    if (error) {
      throw new Error(`Failed to refresh search view: ${error.message}`);
    }

    // Clear cache when view is refreshed
    searchCache.clear();
  }
}