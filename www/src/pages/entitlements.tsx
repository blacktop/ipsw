import React, { useState, useEffect, useCallback } from 'react';
import Layout from '@theme/Layout';
import { createDbWorker } from 'sql.js-httpvfs';

export default function Entitlements() {
    const [dbWorker, setDbWorker] = useState<any>(null);
    const [iosVersions, setIosVersions] = useState<string[]>([]);
    const [selectedVersion, setSelectedVersion] = useState<string>('');
    const [searchType, setSearchType] = useState<'key' | 'file'>('key');
    const [searchQuery, setSearchQuery] = useState<string>('');
    const [results, setResults] = useState<any[]>([]);
    const [loading, setLoading] = useState<boolean>(false);
    const [dbLoading, setDbLoading] = useState<boolean>(true);
    const [error, setError] = useState<string>('');
    const [workerBlobUrl, setWorkerBlobUrl] = useState<string | null>(null);
    const [searchTimeout, setSearchTimeout] = useState<NodeJS.Timeout | null>(null);
    const [isInputFocused, setIsInputFocused] = useState<boolean>(false);
    const [selectedExecutablePath, setSelectedExecutablePath] = useState<string>('');
    const [availableExecutablePaths, setAvailableExecutablePaths] = useState<string[]>([]);
    const [hasSearched, setHasSearched] = useState<boolean>(false);

    useEffect(() => {
        const initDb = async () => {
            if (!dbWorker) {
                const timeoutId = setTimeout(() => {
                    setDbLoading(false);
                    setError('Database initialization timed out. The database file may be missing or corrupted.');
                }, 30000); // Increase timeout to 30 seconds for large database

                try {
                    setDbLoading(true);
                    setError('');


                    let worker;
                    try {
                        // Check for WASM support first
                        if (typeof WebAssembly === 'undefined') {
                            throw new Error('WebAssembly is not supported in this browser');
                        }
                        
                        // Determine base URL for development vs production
                        const isDev = process.env.NODE_ENV === 'development';
                        const currentPath = window.location.pathname;
                        let basePath = '';
                        
                        if (isDev) {
                            // In development, Docusaurus serves static files from /ipsw/ even in dev mode
                            basePath = window.location.origin + '/ipsw';
                        } else {
                            // In production, handle the /ipsw base URL
                            basePath = window.location.origin + '/ipsw';
                        }
                        
                        
                        // Create blob URL for worker to avoid MIME type issues
                        let workerUrl, wasmUrl;
                        try {
                            
                            // Fetch the worker file and create a blob URL
                            const workerResponse = await fetch(`${basePath}/sqlite.worker.js`);
                            if (!workerResponse.ok) {
                                throw new Error(`Worker fetch failed: ${workerResponse.status}`);
                            }
                            const workerBlob = await workerResponse.blob();
                            workerUrl = URL.createObjectURL(new Blob([workerBlob], { type: 'application/javascript' }));
                            setWorkerBlobUrl(workerUrl); // Store for cleanup
                            
                            // WASM file can be loaded directly
                            wasmUrl = `${basePath}/sql-wasm.wasm`;
                            
                        } catch (fetchError) {
                            console.error('Failed to fetch worker files:', fetchError);
                            throw new Error(`Failed to fetch worker files: ${fetchError.message}`);
                        }
                        
                        // Detect connection speed and adjust chunk size accordingly
                        let requestChunkSize = 4096; // Default: 4KB (SQLite page size)
                        
                        // Use Network Information API if available
                        const connection = (navigator as any).connection || (navigator as any).mozConnection || (navigator as any).webkitConnection;
                        if (connection) {
                            const effectiveType = connection.effectiveType;
                            const downlink = connection.downlink; // Mbps
                            
                            // Adjust chunk size based on connection quality
                            if (effectiveType === '4g' || (downlink && downlink > 10)) {
                                requestChunkSize = 262144; // 256KB for fast connections
                            } else if (effectiveType === '3g' || (downlink && downlink > 2)) {
                                requestChunkSize = 65536; // 64KB for medium connections
                            } else if (effectiveType === '2g' || effectiveType === 'slow-2g') {
                                requestChunkSize = 4096; // 4KB for slow connections
                            } else {
                                // Default to larger chunks if we can't determine speed
                                requestChunkSize = 131072; // 128KB
                            }
                        } else {
                            // No Network Information API, use a reasonable default for modern connections
                            requestChunkSize = 131072; // 128KB
                        }

                        worker = await createDbWorker(
                            [{
                                from: 'inline',
                                config: {
                                    serverMode: 'full',
                                    requestChunkSize: requestChunkSize,
                                    url: `${basePath}/db/ipsw.db`,
                                    // Enable caching for better performance
                                    cacheBust: false
                                }
                            }],
                            workerUrl,
                            wasmUrl
                        );
                        
                        // Test if database is accessible and prefetch initial data
                        try {
                            // This query will force loading of the SQLite header and schema
                            await (worker.db as any).exec('SELECT 1;');
                            
                            // Prefetch the iOS versions to cache the index pages
                            await (worker.db as any).exec(
                                `SELECT DISTINCT ios_version FROM entitlement_keys LIMIT 1;`
                            );
                        } catch (connectivityError) {
                            console.error('Database connectivity test failed:', connectivityError);
                            throw new Error(`Database connectivity test failed: ${connectivityError.message}`);
                        }
                        
                    } catch (workerError) {
                        console.error('Failed to create database worker:', workerError);
                        clearTimeout(timeoutId);
                        throw new Error(`Failed to load database worker: ${workerError.message}`);
                    }

                    clearTimeout(timeoutId);

                    // Validate database schema
                    try {
                        const tableRes = await (worker.db as any).exec(
                            `SELECT name FROM sqlite_master WHERE type='table';`
                        );

                        let tables: string[] = [];
                        if (tableRes && tableRes.length > 0 && tableRes[0] && tableRes[0].values) {
                            tables = tableRes[0].values.map((row: any[]) => row[0] as string);
                        }

                        if (tables.length === 0) {
                            throw new Error('Database is empty or corrupted. No tables found.');
                        }

                        if (!tables.includes('entitlement_keys')) {
                            throw new Error(`Database schema mismatch. Expected 'entitlement_keys' table but found tables: ${tables.join(', ')}`);
                        }

                        // Check schema for new columns
                        const schemaRes = await (worker.db as any).exec(
                            `PRAGMA table_info(entitlement_keys);`
                        );

                        let columns: string[] = [];
                        if (schemaRes && schemaRes.length > 0 && schemaRes[0] && schemaRes[0].values) {
                            columns = schemaRes[0].values.map((row: any[]) => row[1]);
                        }

                        const requiredColumns = ['file_path', 'key', 'ios_version'];
                        const missingColumns = requiredColumns.filter(col => !columns.includes(col));

                        if (missingColumns.length > 0) {
                            throw new Error(`Database schema mismatch. Missing required columns: ${missingColumns.join(', ')}`);
                        }

                        // Get available iOS versions
                        const versionsRes = await (worker.db as any).exec(
                            `SELECT DISTINCT ios_version FROM entitlement_keys ORDER BY ios_version DESC;`
                        );

                        let versions: string[] = [];
                        if (versionsRes && versionsRes.length > 0 && versionsRes[0] && versionsRes[0].values) {
                            versions = versionsRes[0].values.map((row: any[]) => row[0] as string).filter((v: string) => v);
                        }
                        setIosVersions(versions);

                        // Test query
                        const testRes = await (worker.db as any).exec(
                            `SELECT COUNT(*) FROM entitlement_keys LIMIT 1;`
                        );

                        let count = 0;
                        if (testRes && testRes.length > 0 && testRes[0] && testRes[0].values && testRes[0].values.length > 0) {
                            count = testRes[0].values[0][0] || 0;
                        }

                        if (count === 0) {
                            throw new Error('Database contains no data. No entitlement records found.');
                        }

                    } catch (validationError) {
                        console.error('Database validation failed:', validationError);
                        throw new Error(`Database validation failed: ${validationError.message}`);
                    }

                    setDbWorker(worker);
                } catch (err) {
                    console.error('Failed to initialize database:', err);
                    clearTimeout(timeoutId);
                    setError(`Failed to initialize database: ${err.message}`);
                } finally {
                    setDbLoading(false);
                }
            }
        };
        initDb();
    }, [dbWorker]);

    // Cleanup blob URL and timeout on unmount
    useEffect(() => {
        return () => {
            if (workerBlobUrl) {
                URL.revokeObjectURL(workerBlobUrl);
            }
            if (searchTimeout) {
                clearTimeout(searchTimeout);
            }
        };
    }, [workerBlobUrl, searchTimeout]);

    // Debounced search function with optional path parameter
    const debouncedSearchWithPath = useCallback(async (query: string, version: string, type: 'key' | 'file', pathFilter: string = '', forceSearch = false) => {
        if (!dbWorker) {
            setError('Database not initialized yet');
            return;
        }

        if (!query.trim()) {
            setResults([]);
            setError('');
            setHasSearched(false);
            return;
        }

        // Don't search if input is focused (user is still typing) unless forced
        if (isInputFocused && !forceSearch) {
            return;
        }

        try {
            setLoading(true);
            setError('');

            let sqlQuery = '';
            let params: any[] = [];

            if (type === 'key') {
                sqlQuery = `
                    SELECT DISTINCT file_path, key, value_type, string_value, bool_value, number_value, array_value, dict_value, ios_version, build_id, device_list
                    FROM entitlement_keys 
                    WHERE key LIKE ?
                `;
                params = [`%${query}%`];
            } else {
                sqlQuery = `
                    SELECT DISTINCT file_path, key, value_type, string_value, bool_value, number_value, array_value, dict_value, ios_version, build_id, device_list
                    FROM entitlement_keys 
                    WHERE file_path LIKE ?
                `;
                params = [`%${query}%`];
            }

            // Add iOS version filter if selected
            if (version) {
                sqlQuery += ` AND ios_version = ?`;
                params.push(version);
            }

            // Add executable path filter if selected
            const effectivePathFilter = pathFilter || selectedExecutablePath;
            if (effectivePathFilter) {
                sqlQuery += ` AND file_path = ?`;
                params.push(effectivePathFilter);
            }

            sqlQuery += ` ORDER BY file_path, key LIMIT 200`;

            const res = await (dbWorker.db as any).exec(sqlQuery, params);

            let searchResults: any[] = [];
            if (res && res.length > 0 && res[0] && res[0].values) {
                searchResults = res[0].values.map((row: any[]) => ({
                    file_path: row[0],
                    key: row[1],
                    value_type: row[2],
                    string_value: row[3],
                    bool_value: row[4],
                    number_value: row[5],
                    array_value: row[6],
                    dict_value: row[7],
                    ios_version: row[8],
                    build_id: row[9],
                    device_list: row[10]
                }));
            }

            setResults(searchResults);
            setHasSearched(true);

            // Extract unique executable paths for the filter dropdown
            if (!effectivePathFilter && searchResults.length > 0) {
                const uniquePaths = Array.from(new Set(searchResults.map(r => r.file_path))).sort();
                setAvailableExecutablePaths(uniquePaths);
            }
        } catch (err) {
            console.error('Search failed:', err);
            setError(`Search failed: ${err.message}`);
            setResults([]);
        } finally {
            setLoading(false);
        }
    }, [dbWorker, isInputFocused, selectedExecutablePath]);

    // Original debouncedSearch function for backward compatibility
    const debouncedSearch = useCallback(async (query: string, version: string, type: 'key' | 'file', forceSearch = false) => {
        return debouncedSearchWithPath(query, version, type, '', forceSearch);
    }, [debouncedSearchWithPath]);

    // Handle search with debouncing
    const handleSearchInput = useCallback((newQuery: string) => {
        setSearchQuery(newQuery);
        
        // Clear executable path filter when starting a new search
        setSelectedExecutablePath('');
        setAvailableExecutablePaths([]);
        setHasSearched(false);
        
        // Clear existing timeout
        if (searchTimeout) {
            clearTimeout(searchTimeout);
        }

        // Set new timeout for debounced search with longer delay when input is focused
        const timeout = setTimeout(() => {
            debouncedSearch(newQuery, selectedVersion, searchType, false);
        }, isInputFocused ? 1000 : 500); // 1000ms when focused, 500ms when not

        setSearchTimeout(timeout);
    }, [selectedVersion, searchType, debouncedSearch, searchTimeout, isInputFocused]);

    // Handle version change
    const handleVersionChange = useCallback((newVersion: string) => {
        setSelectedVersion(newVersion);
        // If there's a search query, re-run the search with the new version (force it)
        if (searchQuery.trim()) {
            debouncedSearch(searchQuery, newVersion, searchType, true);
        }
    }, [searchQuery, searchType, debouncedSearch]);

    // Handle search type change
    const handleSearchTypeChange = useCallback((newType: 'key' | 'file') => {
        setSearchType(newType);
        // If there's a search query, re-run the search with the new type (force it)
        if (searchQuery.trim()) {
            debouncedSearch(searchQuery, selectedVersion, newType, true);
        }
    }, [searchQuery, selectedVersion, debouncedSearch]);

    // Manual search trigger (for search button)
    const handleSearch = async () => {
        // Clear any pending debounced search
        if (searchTimeout) {
            clearTimeout(searchTimeout);
        }
        // Execute search immediately (force it)
        await debouncedSearch(searchQuery, selectedVersion, searchType, true);
    };

    // Handle input focus/blur events
    const handleInputFocus = useCallback(() => {
        setIsInputFocused(true);
    }, []);

    const handleInputBlur = useCallback(() => {
        setIsInputFocused(false);
        // When input loses focus, trigger search if there's a query
        if (searchQuery.trim()) {
            // Small delay to allow for the search to happen after blur
            setTimeout(() => {
                debouncedSearch(searchQuery, selectedVersion, searchType, true);
            }, 100);
        }
    }, [searchQuery, selectedVersion, searchType, debouncedSearch]);

    // Handle executable path filter change
    const handleExecutablePathChange = useCallback((newPath: string) => {
        setSelectedExecutablePath(newPath);
        // If changing from "All executables" to a specific path, clear the available paths
        if (newPath !== '') {
            setAvailableExecutablePaths([]);
        }
        // If there's a search query, re-run the search with the new path filter
        if (searchQuery.trim()) {
            // Pass the new path directly instead of relying on state
            debouncedSearchWithPath(searchQuery, selectedVersion, searchType, newPath, true);
        }
    }, [searchQuery, selectedVersion, searchType]);

    const formatValue = (result: any) => {
        switch (result.value_type) {
            case 'bool':
                return {
                    type: 'bool',
                    value: result.bool_value,
                    display: result.bool_value ? 'true' : 'false'
                };
            case 'number':
                return {
                    type: 'number',
                    value: result.number_value,
                    display: result.number_value?.toString() || ''
                };
            case 'string':
                return {
                    type: 'string',
                    value: result.string_value,
                    display: result.string_value || ''
                };
            case 'array':
                try {
                    const arrayValue = JSON.parse(result.array_value || '[]');
                    return {
                        type: 'array',
                        value: arrayValue,
                        display: result.array_value || ''
                    };
                } catch {
                    return {
                        type: 'array',
                        value: [],
                        display: result.array_value || ''
                    };
                }
            case 'dict':
                try {
                    const dictValue = JSON.parse(result.dict_value || '{}');
                    return {
                        type: 'dict',
                        value: dictValue,
                        display: result.dict_value || ''
                    };
                } catch {
                    return {
                        type: 'dict',
                        value: {},
                        display: result.dict_value || ''
                    };
                }
            case 'object': // Handle legacy object type
                try {
                    const objectValue = JSON.parse(result.dict_value || '{}');
                    return {
                        type: 'dict',
                        value: objectValue,
                        display: result.dict_value || ''
                    };
                } catch {
                    return {
                        type: 'dict',
                        value: {},
                        display: result.dict_value || ''
                    };
                }
            default:
                return {
                    type: 'unknown',
                    value: 'true',
                    display: 'true'
                };
        }
    };

    return (
        <Layout title="Entitlements">
            <div className="entitlements-container">
                <div className="entitlements-header">
                    <h1 className="entitlements-title">Entitlements Browser</h1>
                    <p className="entitlements-subtitle">
                        Search for entitlement keys and files across iOS system binaries.
                    </p>
                </div>

                {dbLoading && (
                    <div className="loading-banner">
                        <div className="loading-spinner"></div>
                        <div className="loading-text">
                            <span>Loading entitlements database...</span>
                            <span className="loading-subtitle">Optimizing for your connection speed</span>
                        </div>
                    </div>
                )}

                {error && !dbLoading && (
                    <div className="error-banner">
                        <strong>Database Error:</strong> {error}
                    </div>
                )}

                {!dbLoading && !error && dbWorker && (
                    <div className="search-wrapper">
                        <div className="search-panel">
                            {/* Top Row: Version Filter and Search Type */}
                            <div className="form-row">
                                <div className="form-group">
                                    <label className="form-label">
                                        iOS Version Filter
                                    </label>
                                    <select
                                        value={selectedVersion}
                                        onChange={(e) => handleVersionChange(e.target.value)}
                                        className="form-select"
                                    >
                                        <option value="">All versions</option>
                                        {iosVersions.map(version => (
                                            <option key={version} value={version}>{version}</option>
                                        ))}
                                    </select>
                                </div>

                                <div className="form-group">
                                    <label className="form-label">
                                        Search Type
                                    </label>
                                    <div className="radio-group">
                                        <label className="radio-option">
                                            <input
                                                type="radio"
                                                value="key"
                                                checked={searchType === 'key'}
                                                onChange={(e) => handleSearchTypeChange(e.target.value as 'key' | 'file')}
                                                className="radio-input"
                                            />
                                            <span className="radio-label">Entitlement Key</span>
                                        </label>
                                        <label className="radio-option">
                                            <input
                                                type="radio"
                                                value="file"
                                                checked={searchType === 'file'}
                                                onChange={(e) => handleSearchTypeChange(e.target.value as 'key' | 'file')}
                                                className="radio-input"
                                            />
                                            <span className="radio-label">Executable Path</span>
                                        </label>
                                    </div>
                                </div>
                            </div>

                            {/* Executable Path Filter - full width row */}
                            {(availableExecutablePaths.length > 1 || selectedExecutablePath) && (
                                <div className="form-group form-group--full-width">
                                    <label className="form-label">
                                        Executable Filter
                                    </label>
                                    <select
                                        value={selectedExecutablePath}
                                        onChange={(e) => handleExecutablePathChange(e.target.value)}
                                        className="form-select form-select--executable"
                                    >
                                        <option value="">
                                            {availableExecutablePaths.length > 0 
                                                ? `All executables (${availableExecutablePaths.length})`
                                                : 'All executables'
                                            }
                                        </option>
                                        {(() => {
                                            // If we have a selected path but no available paths, show just the selected one
                                            if (selectedExecutablePath && availableExecutablePaths.length === 0) {
                                                const basename = selectedExecutablePath.split('/').pop() || selectedExecutablePath;
                                                return (
                                                    <option key={selectedExecutablePath} value={selectedExecutablePath}>
                                                        {basename}
                                                    </option>
                                                );
                                            }
                                            
                                            // Always show full paths to avoid ambiguity
                                            return availableExecutablePaths.map(path => {
                                                const basename = path.split('/').pop() || path;
                                                // Show basename first, then full path for clarity
                                                const displayName = path.length > 50 ? 
                                                    `${basename} - ${path.substring(0, 47)}...` : 
                                                    `${basename} - ${path}`;
                                                
                                                return (
                                                    <option key={path} value={path}>
                                                        {displayName}
                                                    </option>
                                                );
                                            });
                                        })()}
                                    </select>
                                </div>
                            )}

                        {/* Search Input */}
                        <div className="form-group">
                            <label className="form-label">
                                Search {searchType === 'key' ? 'Entitlement Keys' : 'Executable Paths'}
                            </label>
                            <div className="search-input-group">
                                <input
                                    type="text"
                                    value={searchQuery}
                                    onChange={(e) => handleSearchInput(e.target.value)}
                                    onFocus={handleInputFocus}
                                    onBlur={handleInputBlur}
                                    placeholder={searchType === 'key' 
                                        ? 'Enter entitlement key (e.g., com.apple.security.app-sandbox)' 
                                        : 'Enter executable name (e.g., WebContent, Safari)'
                                    }
                                    className="search-input"
                                    disabled={loading}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' && !loading && searchQuery.trim()) {
                                            handleSearch();
                                        }
                                    }}
                                />
                                <button
                                    onClick={handleSearch}
                                    className={`search-button ${(!loading && searchQuery.trim()) ? 'search-button--active' : 'search-button--disabled'}`}
                                    disabled={loading || !searchQuery.trim()}
                                >
                                    {loading ? 'Searching...' : 'Search'}
                                </button>
                            </div>
                        </div>

                        {/* No Results Warning */}
                        {!loading && hasSearched && searchQuery.trim() && results.length === 0 && (
                            <div className="no-results-warning">
                                <span className="warning-icon">⚠️</span>
                                <div className="warning-content">
                                    <div className="warning-text">
                                        No entitlements found for <strong>"{searchQuery}"</strong>
                                        {selectedVersion && <span> in iOS {selectedVersion}</span>}
                                        {selectedExecutablePath && <span> in {selectedExecutablePath}</span>}
                                    </div>
                                    <div className="warning-hint">Try adjusting your search terms or filters</div>
                                </div>
                            </div>
                        )}

                        {/* Results */}
                        <div className="results-section">
                            {results.length > 0 ? (
                                <div>
                                    <div className="results-header-row">
                                        <h3 className="results-header">
                                            Found {results.length} result{results.length === 1 ? '' : 's'}
                                        </h3>
                                    </div>

                                    {/* Show global metadata if version is selected or executable is filtered (but not when searching by executable path) */}
                                    {(selectedVersion || (selectedExecutablePath && searchType === 'key')) && results.length > 0 && (
                                        <div className="global-metadata">
                                            iOS {results[0].ios_version} ({results[0].build_id}) • {results[0].device_list}
                                            {selectedExecutablePath && searchType === 'key' && (
                                                <> • {selectedExecutablePath.split('/').pop()}</>
                                            )}
                                        </div>
                                    )}

                                    <div className="results-container">
                                        {results.map((result, idx) => {
                                            const valueData = formatValue(result);
                                            const showMetadata = !selectedVersion; // Only show metadata in each item if no version selected
                                            // Hide file path if filtered to specific executable OR if searching by file and all results have the same path
                                            const allSamePath = searchType === 'file' && results.every(r => r.file_path === results[0].file_path);
                                            const showFilePath = !selectedExecutablePath && !allSamePath;
                                            
                                            return (
                                                <div key={idx} className="result-item">
                                                    <div className="result-main">
                                                        <span className="result-key">{result.key}</span>
                                                        {showFilePath && (
                                                            <>
                                                                <span className="result-in"> in </span>
                                                                <span className="result-path">{result.file_path}</span>
                                                            </>
                                                        )}
                                                    </div>
                                                    
                                                    {showMetadata && (
                                                        <div className="result-meta">
                                                            iOS {result.ios_version} ({result.build_id}) • {result.device_list}
                                                        </div>
                                                    )}
                                                    
                                                    {valueData && valueData.display && (
                                                        <div className="result-value">
                                                            {valueData.type === 'bool' ? (
                                                                <span className={`bool-value ${valueData.value ? 'bool-true' : 'bool-false'}`}>
                                                                    {valueData.display}
                                                                </span>
                                                            ) : valueData.type === 'array' && Array.isArray(valueData.value) ? (
                                                                // Check if array contains objects
                                                                valueData.value.length > 0 && typeof valueData.value[0] === 'object' && valueData.value[0] !== null ? (
                                                                    <div className="array-dict-value">
                                                                        {valueData.value.map((item, itemIdx) => (
                                                                            <div key={itemIdx} className="dict-item">
                                                                                {typeof item === 'object' && item !== null ? (
                                                                                    Object.entries(item).map(([key, val], entryIdx) => (
                                                                                        <div key={entryIdx} className="dict-entry">
                                                                                            <span className="dict-key">{key}</span>
                                                                                            <span className="dict-sep">→</span>
                                                                                            <span className="dict-val">{String(val)}</span>
                                                                                        </div>
                                                                                    ))
                                                                                ) : (
                                                                                    <span>{String(item)}</span>
                                                                                )}
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                ) : (
                                                                    <ul className="array-value">
                                                                        {valueData.value.map((item, itemIdx) => (
                                                                            <li key={itemIdx}>{String(item)}</li>
                                                                        ))}
                                                                    </ul>
                                                                )
                                                            ) : valueData.type === 'dict' && typeof valueData.value === 'object' ? (
                                                                <div className="dict-value">
                                                                    {Array.isArray(valueData.value) ? (
                                                                        valueData.value.map((item, itemIdx) => (
                                                                            <div key={itemIdx} className="dict-item">
                                                                                {typeof item === 'object' ? (
                                                                                    Object.entries(item).map(([key, val], entryIdx) => (
                                                                                        <div key={entryIdx} className="dict-entry">
                                                                                            <span className="dict-key">{key}</span>
                                                                                            <span className="dict-sep">→</span>
                                                                                            <span className="dict-val">{String(val)}</span>
                                                                                        </div>
                                                                                    ))
                                                                                ) : (
                                                                                    <span className="dict-simple">{String(item)}</span>
                                                                                )}
                                                                            </div>
                                                                        ))
                                                                    ) : (
                                                                        Object.entries(valueData.value).map(([key, val], entryIdx) => (
                                                                            <div key={entryIdx} className="dict-entry">
                                                                                <span className="dict-key">{key}</span>
                                                                                <span className="dict-sep">→</span>
                                                                                <span className="dict-val">{String(val)}</span>
                                                                            </div>
                                                                        ))
                                                                    )}
                                                                </div>
                                                            ) : (
                                                                <span className="regular-value">{valueData.display}</span>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            ) : null}
                        </div>
                    </div>
                    </div>
                )}
            </div>

            <style>{`
                .entitlements-container {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #1a1a1a 0%, #2d3748 100%);
                    padding: 2rem;
                    color: var(--ifm-color-content);
                    display: flex;
                    flex-direction: column;
                }

                .entitlements-header {
                    text-align: center;
                    margin-bottom: 3rem;
                    max-width: 800px;
                    margin-left: auto;
                    margin-right: auto;
                    flex-shrink: 0;
                }

                .entitlements-title {
                    font-size: 3rem;
                    font-weight: 700;
                    background: linear-gradient(135deg, #60a5fa, #a78bfa, #f472b6);
                    background-clip: text;
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    margin-bottom: 1rem;
                    letter-spacing: -0.025em;
                }

                .entitlements-subtitle {
                    font-size: 1.25rem;
                    color: var(--ifm-color-content-secondary);
                    line-height: 1.6;
                    margin: 0;
                }

                .loading-banner {
                    background: rgba(31, 41, 55, 0.8);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(75, 85, 99, 0.3);
                    border-radius: 12px;
                    padding: 1.5rem;
                    margin-bottom: 2rem;
                    display: flex;
                    align-items: center;
                    gap: 1rem;
                    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
                    color: var(--ifm-color-content);
                    max-width: 1000px;
                    margin-left: auto;
                    margin-right: auto;
                    flex-shrink: 0;
                }

                .loading-text {
                    display: flex;
                    flex-direction: column;
                    gap: 0.25rem;
                }

                .loading-subtitle {
                    font-size: 0.875rem;
                    color: var(--ifm-color-content-secondary);
                    opacity: 0.8;
                }

                .loading-spinner {
                    width: 20px;
                    height: 20px;
                    border-radius: 50%;
                    background: conic-gradient(#a78bfa, #60a5fa, #f472b6, #a78bfa);
                    animation: spin 1s linear infinite;
                    flex-shrink: 0;
                }

                .error-banner {
                    background: linear-gradient(135deg, #7f1d1d, #991b1b);
                    border: 1px solid #ef4444;
                    border-radius: 12px;
                    padding: 1.5rem;
                    margin-bottom: 2rem;
                    color: #fecaca;
                    box-shadow: 0 4px 20px rgba(239, 68, 68, 0.15);
                    flex-shrink: 0;
                }

                .search-wrapper {
                    width: 100%;
                    max-width: 1000px;
                    margin: 0 auto;
                    display: flex;
                    flex-direction: column;
                    flex: 1;
                }

                .search-panel {
                    background: rgba(31, 41, 55, 0.8);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(75, 85, 99, 0.3);
                    border-radius: 16px;
                    padding: 2rem;
                    width: 100%;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                    display: flex;
                    flex-direction: column;
                }

                .form-row {
                    display: flex;
                    gap: 3rem;
                    align-items: flex-start;
                    margin-bottom: 1rem;
                    flex-wrap: wrap;
                }

                .form-group {
                    margin-bottom: 1rem;
                    flex: 1;
                    min-width: 280px;
                }

                .form-group--full-width {
                    width: 100%;
                    flex: none;
                    min-width: 100%;
                    margin-top: 0.5rem;
                }

                .form-label {
                    display: block;
                    font-weight: 600;
                    color: #9ca3af;
                    margin-bottom: 0.75rem;
                    font-size: 0.95rem;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }

                .form-select {
                    width: 100%;
                    max-width: 300px;
                    padding: 0.75rem 1rem;
                    font-size: 1rem;
                    background: rgba(55, 65, 81, 0.8);
                    border: 2px solid rgba(75, 85, 99, 0.5);
                    border-radius: 8px;
                    color: var(--ifm-color-content);
                    transition: all 0.2s ease;
                }

                .form-select:focus {
                    outline: none;
                    border-color: #60a5fa;
                    box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.1);
                }

                .form-select option {
                    background: var(--ifm-background-color);
                    color: var(--ifm-color-content);
                }

                .form-select--executable {
                    width: 100%;
                    max-width: none;
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                    font-size: 0.9rem;
                }


                .radio-group {
                    display: flex;
                    gap: 2rem;
                    flex-wrap: wrap;
                }

                .radio-option {
                    display: flex;
                    align-items: center;
                    gap: 0.75rem;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    padding: 0.5rem;
                    border-radius: 8px;
                }

                .radio-option:hover {
                    background: rgba(75, 85, 99, 0.2);
                }

                .radio-input {
                    width: 18px;
                    height: 18px;
                    accent-color: #60a5fa;
                }

                .radio-label {
                    font-size: 1rem;
                    color: var(--ifm-color-content);
                    font-weight: 500;
                }

                .search-input-group {
                    display: flex;
                    gap: 1rem;
                    align-items: stretch;
                }

                .search-input {
                    flex: 1;
                    padding: 1rem 1.25rem;
                    font-size: 1rem;
                    background: rgba(55, 65, 81, 0.8);
                    border: 2px solid rgba(75, 85, 99, 0.5);
                    border-radius: 12px;
                    color: var(--ifm-color-content);
                    transition: all 0.2s ease;
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                }

                .search-input:focus {
                    outline: none;
                    border-color: #60a5fa;
                    box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.1);
                }

                .search-input::placeholder {
                    color: #6b7280;
                    opacity: 0.7;
                }

                .search-input:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }

                .search-button {
                    padding: 1rem 2rem;
                    font-size: 1rem;
                    font-weight: 600;
                    border: none;
                    border-radius: 12px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    min-width: 140px;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }

                .search-button--active {
                    background: linear-gradient(135deg, #3b82f6, #1d4ed8);
                    color: white;
                    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
                }

                .search-button--active:hover {
                    background: linear-gradient(135deg, #2563eb, #1e40af);
                    transform: translateY(-2px);
                    box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4);
                }

                .search-button--disabled {
                    background: rgba(75, 85, 99, 0.5);
                    color: rgba(156, 163, 175, 0.8);
                    cursor: not-allowed;
                }

                .results-section {
                    margin-top: 2rem;
                    flex: 1;
                    display: flex;
                    flex-direction: column;
                    min-height: 0;
                }

                .results-header-row {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 1rem;
                    flex-wrap: wrap;
                    gap: 1rem;
                }

                .results-header {
                    font-size: 1.1rem;
                    font-weight: 600;
                    color: #10b981;
                    margin: 0;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }

                .results-header::before {
                    content: '✓';
                    width: 20px;
                    height: 20px;
                    background: #10b981;
                    color: white;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 0.7rem;
                    font-weight: bold;
                }

                .global-metadata {
                    background: rgba(59, 130, 246, 0.1);
                    border: 1px solid rgba(59, 130, 246, 0.2);
                    border-radius: 8px;
                    padding: 0.75rem 1rem;
                    margin-bottom: 1rem;
                    color: #93c5fd;
                    font-size: 0.9rem;
                    font-weight: 500;
                    text-align: center;
                }

                .results-container {
                    background: rgba(17, 24, 39, 0.8);
                    border: 1px solid rgba(75, 85, 99, 0.3);
                    border-radius: 12px;
                    flex: 1;
                    overflow-y: auto;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                    max-height: calc(100vh - 500px);
                }

                .result-item {
                    padding: 1.5rem;
                    border-bottom: 1px solid rgba(75, 85, 99, 0.2);
                    transition: all 0.2s ease;
                }

                .result-item:last-child {
                    border-bottom: none;
                }

                .result-item:hover {
                    background: rgba(75, 85, 99, 0.1);
                }

                .result-main {
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                    font-size: 0.95rem;
                    margin-bottom: 0.75rem;
                    line-height: 1.5;
                }

                .result-key {
                    color: #60a5fa;
                    font-weight: 600;
                }

                .result-in {
                    color: var(--ifm-color-content-secondary);
                    font-weight: 400;
                }

                .result-path {
                    color: #f472b6;
                    font-weight: 500;
                }

                .result-meta {
                    font-size: 0.85rem;
                    color: var(--ifm-color-content-secondary);
                    margin-bottom: 0.5rem;
                    font-weight: 500;
                }

                .result-value {
                    margin-top: 0.75rem;
                }

                .bool-value {
                    display: inline-block;
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                    font-size: 0.8rem;
                    font-weight: 600;
                    padding: 0.5rem 0.75rem;
                    border-radius: 6px;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    background: rgba(99, 102, 241, 0.1);
                    border: 1px solid rgba(99, 102, 241, 0.2);
                }

                .bool-true {
                    color: #34d399;
                }

                .bool-false {
                    color: #f87171;
                }

                .array-value {
                    background: rgba(99, 102, 241, 0.1);
                    border: 1px solid rgba(99, 102, 241, 0.2);
                    border-radius: 6px;
                    padding: 0.75rem 0.75rem 0.75rem 2rem;
                    margin: 0;
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                    font-size: 0.8rem;
                    color: #e0e7ff;
                }

                .array-value li {
                    padding: 0.25rem 0;
                    border-bottom: 1px solid rgba(99, 102, 241, 0.1);
                }

                .array-value li:last-child {
                    border-bottom: none;
                }

                .array-value li::marker {
                    color: #818cf8;
                }

                .regular-value {
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                    font-size: 0.8rem;
                    background: rgba(99, 102, 241, 0.1);
                    border: 1px solid rgba(99, 102, 241, 0.2);
                    color: #e0e7ff;
                    padding: 0.5rem 0.75rem;
                    border-radius: 6px;
                    word-break: break-all;
                    display: block;
                }

                .array-dict-value {
                    background: rgba(99, 102, 241, 0.1);
                    border: 1px solid rgba(99, 102, 241, 0.2);
                    border-radius: 6px;
                    padding: 0.75rem 1rem;
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                    font-size: 0.8rem;
                }

                .dict-value {
                    background: rgba(168, 85, 247, 0.08);
                    border: 1px solid rgba(168, 85, 247, 0.2);
                    border-radius: 6px;
                    padding: 0.75rem 1rem;
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                    font-size: 0.8rem;
                }

                .array-dict-value .dict-item {
                    margin-bottom: 0.75rem;
                    padding-bottom: 0.75rem;
                    border-bottom: 1px solid rgba(99, 102, 241, 0.1);
                }

                .dict-value .dict-item {
                    margin-bottom: 0.75rem;
                    padding-bottom: 0.75rem;
                    border-bottom: 1px solid rgba(168, 85, 247, 0.1);
                }

                .dict-item:last-child {
                    margin-bottom: 0;
                    padding-bottom: 0;
                    border-bottom: none;
                }

                .dict-entry {
                    display: flex;
                    gap: 0.75rem;
                    margin-bottom: 0.4rem;
                    align-items: center;
                    line-height: 1.4;
                }

                .dict-entry:last-child {
                    margin-bottom: 0;
                }

                .dict-key {
                    color: #ddd6fe;
                    font-weight: 400;
                    min-width: fit-content;
                    flex-shrink: 0;
                }

                .dict-sep {
                    color: #93c5fd;
                    font-weight: 400;
                    flex-shrink: 0;
                }

                .dict-val {
                    color: #e0e7ff;
                    word-break: break-word;
                    flex: 1;
                    font-weight: 400;
                }

                .dict-simple {
                    color: #e0e7ff;
                }

                .no-results-warning {
                    background: rgba(251, 191, 36, 0.1);
                    border: 1px solid rgba(251, 191, 36, 0.3);
                    border-radius: 8px;
                    padding: 1rem 1.25rem;
                    margin-top: 1.5rem;
                    margin-bottom: 1.5rem;
                    display: flex;
                    align-items: flex-start;
                    gap: 0.75rem;
                }

                .warning-icon {
                    font-size: 1.25rem;
                    flex-shrink: 0;
                    margin-top: -0.1rem;
                }

                .warning-content {
                    flex: 1;
                }

                .warning-text {
                    color: #fbbf24;
                    font-size: 0.95rem;
                    line-height: 1.5;
                    margin-bottom: 0.25rem;
                }

                .warning-text strong {
                    color: #fcd34d;
                    font-weight: 600;
                }

                .warning-hint {
                    color: #f59e0b;
                    font-size: 0.85rem;
                    opacity: 0.8;
                }

                @keyframes spin {
                    from { transform: rotate(0deg); }
                    to { transform: rotate(360deg); }
                }

                @media (max-width: 768px) {
                    .entitlements-container {
                        padding: 1rem;
                    }

                    .entitlements-title {
                        font-size: 2rem;
                    }

                    .search-panel {
                        padding: 1.5rem;
                    }

                    .form-row {
                        flex-direction: column;
                        gap: 1.5rem;
                    }

                    .form-group {
                        min-width: auto;
                    }

                    .search-input-group {
                        flex-direction: column;
                    }

                    .radio-group {
                        flex-direction: column;
                        gap: 1rem;
                    }

                    .results-header-row {
                        flex-direction: column;
                        align-items: flex-start;
                    }

                    .executable-filter {
                        width: 100%;
                    }

                    .form-select--small {
                        max-width: 100%;
                    }

                    .result-item {
                        padding: 1rem;
                    }

                    .array-value {
                        padding: 0.5rem;
                    }
                }
            `}</style>
        </Layout>
    );
}