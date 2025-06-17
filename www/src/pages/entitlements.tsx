import React, { useState, useEffect, useCallback } from 'react';
import Layout from '@theme/Layout';
import { EntitlementsService, EntitlementResult } from '../lib/supabase';

export default function Entitlements() {
    const [iosVersions, setIosVersions] = useState<string[]>([]);
    const [selectedVersion, setSelectedVersion] = useState<string>('');
    const [searchType, setSearchType] = useState<'key' | 'file'>('key');
    const [searchQuery, setSearchQuery] = useState<string>('');
    const [results, setResults] = useState<EntitlementResult[]>([]);
    const [loading, setLoading] = useState<boolean>(false);
    const [dbLoading, setDbLoading] = useState<boolean>(true);
    const [error, setError] = useState<string>('');
    const [searchTimeout, setSearchTimeout] = useState<NodeJS.Timeout | null>(null);
    const [isInputFocused, setIsInputFocused] = useState<boolean>(false);
    const [selectedExecutablePath, setSelectedExecutablePath] = useState<string>('');
    const [availableExecutablePaths, setAvailableExecutablePaths] = useState<string[]>([]);
    const [hasSearched, setHasSearched] = useState<boolean>(false);
    const [accordionExpanded, setAccordionExpanded] = useState<boolean>(true);

    useEffect(() => {
        const initSupabase = async () => {
            try {
                setDbLoading(true);
                setError('');

                // Check if Supabase is configured
                if (!EntitlementsService.isConfigured()) {
                    throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
                }

                const isConnected = await EntitlementsService.testConnection();

                if (!isConnected) {
                    throw new Error('Failed to connect to Supabase. Please check your configuration.');
                }

                const versions = await EntitlementsService.getIosVersions();
                setIosVersions(versions);
            } catch (err) {
                console.error('Failed to initialize database:', err);
                setError(`Failed to initialize database: ${err.message}`);
            } finally {
                setDbLoading(false);
            }
        };

        initSupabase();
    }, []);

    // Cleanup timeout on unmount
    useEffect(() => {
        return () => {
            if (searchTimeout) {
                clearTimeout(searchTimeout);
            }
        };
    }, [searchTimeout]);

    // Debounced search function with optional path parameter
    const debouncedSearchWithPath = useCallback(async (query: string, version: string, type: 'key' | 'file', pathFilter: string = '', forceSearch = false) => {
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

            // Use the effective path filter
            const effectivePathFilter = pathFilter || selectedExecutablePath;

            let searchResults: EntitlementResult[];
            if (type === 'key') {
                searchResults = await EntitlementsService.searchByKey(
                    query,
                    version || undefined,
                    effectivePathFilter || undefined,
                    200
                );
            } else {
                searchResults = await EntitlementsService.searchByFile(
                    query,
                    version || undefined,
                    effectivePathFilter || undefined,
                    200
                );
            }

            setResults(searchResults);
            setHasSearched(true);

            // Auto-collapse accordion after successful search with results
            if (searchResults.length > 0 && accordionExpanded) {
                setTimeout(() => setAccordionExpanded(false), 300);
            }

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
    }, [isInputFocused, selectedExecutablePath, accordionExpanded]);

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
                            <span>Connecting to database...</span>
                        </div>
                    </div>
                )}

                {error && !dbLoading && (
                    <div className="error-banner">
                        <strong>Database Error:</strong> {error}

                        {error.includes('Database is not configured') && (
                            <div style={{ marginTop: '1rem', fontSize: '0.9rem' }}>
                                <p><strong>Setup Instructions:</strong></p>
                                <ol style={{ marginLeft: '1rem', lineHeight: '1.6' }}>
                                    <li>Create a Supabase project at <a href="https://supabase.com" target="_blank" rel="noopener noreferrer" style={{ color: '#60a5fa' }}>supabase.com</a></li>
                                    <li>Run the schema from <code>supabase/schema.sql</code> in your Supabase SQL editor</li>
                                    <li>Generate data using: <code>ipsw ent --pg-host db.your-project.supabase.co --pg-user postgres --pg-password your-password --pg-database postgres --ipsw your-file.ipsw</code></li>
                                    <li>Set environment variables: <code>REACT_APP_SUPABASE_URL</code> and <code>REACT_APP_SUPABASE_ANON_KEY</code></li>
                                </ol>
                                <p>See <code>README-SUPABASE.md</code> for detailed instructions.</p>
                            </div>
                        )}
                    </div>
                )}

                {!dbLoading && !error && (
                    <div className="search-wrapper">
                        <div className="search-accordion">
                            {/* Accordion Header */}
                            <button
                                className="accordion-header"
                                onClick={() => setAccordionExpanded(!accordionExpanded)}
                                type="button"
                                aria-expanded={accordionExpanded}
                            >
                                <div className="accordion-title">
                                    <span className="accordion-icon"></span>
                                    <span>Search & Filters</span>
                                    {hasSearched && !accordionExpanded && (
                                        <span className="active-search-indicator">
                                            {searchQuery && `"${searchQuery}"`}
                                            {selectedExecutablePath && ` • ${selectedExecutablePath.split('/').pop()}`}
                                        </span>
                                    )}
                                </div>
                                <div className={`accordion-chevron ${accordionExpanded ? 'accordion-chevron--expanded' : ''}`}>
                                    ▼
                                </div>
                            </button>

                            {/* Accordion Content */}
                            {accordionExpanded && (
                                <div className="accordion-content">
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
                                </div>
                            )}
                        </div>

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
                                            iOS {results[0].ios_version} ({results[0].build_id}){results[0].device_list && ` • ${results[0].device_list}`}
                                            {selectedExecutablePath && searchType === 'key' && (
                                                <> • {selectedExecutablePath.split('/').pop()}</>
                                            )}
                                        </div>
                                    )}

                                    <div className={`results-container ${!accordionExpanded ? 'results-container--expanded' : ''}`}>
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
                                                            iOS {result.ios_version} ({result.build_id}){result.device_list && ` • ${result.device_list}`}
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
                    color: var(--ifm-color-primary);
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
                    gap: 0.75rem;
                    flex: 1;
                }

                .progress-container {
                    display: flex;
                    align-items: center;
                    gap: 1rem;
                }

                .progress-bar {
                    flex: 1;
                    height: 8px;
                    background: rgba(75, 85, 99, 0.3);
                    border-radius: 4px;
                    overflow: hidden;
                }

                .progress-fill {
                    height: 100%;
                    background: linear-gradient(90deg, #60a5fa, #a78bfa, #f472b6);
                    border-radius: 4px;
                    transition: width 0.3s ease;
                }

                .progress-text {
                    font-size: 0.875rem;
                    color: var(--ifm-color-content-secondary);
                    font-weight: 600;
                    min-width: 45px;
                    text-align: right;
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

                .search-accordion {
                    background: rgba(31, 41, 55, 0.8);
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(75, 85, 99, 0.3);
                    border-radius: 16px;
                    width: 100%;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                    overflow: hidden;
                    margin-bottom: 1rem;
                }

                .accordion-header {
                    width: 100%;
                    padding: 1.5rem 2rem;
                    background: transparent;
                    border: none;
                    cursor: pointer;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    transition: all 0.2s ease;
                    color: var(--ifm-color-content);
                }

                .accordion-header:hover {
                    background: rgba(75, 85, 99, 0.1);
                }

                .accordion-title {
                    display: flex;
                    align-items: center;
                    gap: 0.75rem;
                    font-size: 1.1rem;
                    font-weight: 600;
                    flex: 1;
                }

                .accordion-icon {
                    width: 16px;
                    height: 16px;
                    border: 2px solid currentColor;
                    border-radius: 50%;
                    opacity: 0.6;
                    position: relative;
                    flex-shrink: 0;
                }

                .accordion-icon::after {
                    content: '';
                    position: absolute;
                    width: 6px;
                    height: 2px;
                    background: currentColor;
                    border-radius: 1px;
                    top: 12px;
                    left: 12px;
                    transform: rotate(45deg);
                    transform-origin: 0 50%;
                }

                .active-search-indicator {
                    font-size: 0.85rem;
                    color: var(--ifm-color-content-secondary);
                    font-weight: 400;
                    margin-left: 1rem;
                    opacity: 0.8;
                    font-family: 'SF Mono', Monaco, Inconsolata, 'Roboto Mono', monospace;
                }

                .accordion-chevron {
                    font-size: 0.8rem;
                    color: var(--ifm-color-content-secondary);
                    transition: transform 0.2s ease;
                    transform: rotate(0deg);
                }

                .accordion-chevron--expanded {
                    transform: rotate(180deg);
                }

                .accordion-content {
                    padding: 0 2rem 2rem 2rem;
                    animation: slideDown 0.2s ease-out;
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


                @keyframes slideDown {
                    from {
                        opacity: 0;
                        transform: translateY(-10px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }

                @media (max-width: 768px) {
                    .accordion-header {
                        padding: 1.25rem 1.5rem;
                    }
                    
                    .accordion-content {
                        padding: 0 1.5rem 1.5rem 1.5rem;
                    }
                    
                    .accordion-title {
                        font-size: 1rem;
                    }
                    
                    .active-search-indicator {
                        font-size: 0.75rem;
                        margin-left: 0.5rem;
                    }
                    
                    .results-container {
                        max-height: calc(100vh - 400px);
                    }
                    
                    .results-container--expanded {
                        max-height: calc(100vh - 220px);
                    }
                }

                .results-section {
                    margin-top: 0;
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

                .results-container--expanded {
                    max-height: calc(100vh - 350px);
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

                /* Hide footer on this page for cleaner full-screen experience */
                footer[class*="footer"] {
                    display: none !important;
                }
                    `}</style>
        </Layout>
    );
}