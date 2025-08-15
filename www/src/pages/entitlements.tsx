import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import Layout from '@theme/Layout';
import { EntitlementsService, EntitlementResult } from '../lib/supabase';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../components/ui/collapsible';
import { Search, Filter, ChevronDown, ChevronUp, AlertCircle, Loader2, Database, Code, FileText, Smartphone } from 'lucide-react';
import { cn, debounce, highlightSearchTerm, formatEntitlementValue, getValueTypeColor, sortVersions } from '../lib/utils';
import '../css/entitlements.css';

// Type definitions
interface FormattedValue {
    type: 'bool' | 'number' | 'string' | 'array' | 'dict' | 'unknown';
    value: any;
    display: string;
}

interface ErrorWithMessage {
    message: string;
}

function isErrorWithMessage(error: unknown): error is ErrorWithMessage {
    return (
        typeof error === 'object' &&
        error !== null &&
        'message' in error &&
        typeof (error as Record<string, unknown>).message === 'string'
    );
}

function toErrorWithMessage(maybeError: unknown): ErrorWithMessage {
    if (isErrorWithMessage(maybeError)) return maybeError;

    try {
        return new Error(JSON.stringify(maybeError));
    } catch {
        return new Error(String(maybeError));
    }
}

export default function Entitlements() {
    const [versions, setVersions] = useState<string[]>([]);
    const [selectedVersion, setSelectedVersion] = useState<string>('');
    const [selectedPlatform, setSelectedPlatform] = useState<string>('iOS');
    const [searchType, setSearchType] = useState<'key' | 'file'>('key');
    const [searchQuery, setSearchQuery] = useState<string>('');
    const [results, setResults] = useState<EntitlementResult[]>([]);
    const [loading, setLoading] = useState<boolean>(false);
    const [dbLoading, setDbLoading] = useState<boolean>(true);
    const [error, setError] = useState<string>('');
    const [selectedExecutablePath, setSelectedExecutablePath] = useState<string>('');
    const [availableExecutablePaths, setAvailableExecutablePaths] = useState<string[]>([]);
    const [hasSearched, setHasSearched] = useState<boolean>(false);
    const [filtersOpen, setFiltersOpen] = useState<boolean>(true);
    const [isMobile, setIsMobile] = useState<boolean>(false);

    const availablePlatforms = ['iOS', 'macOS'];

    const abortControllerRef = useRef<AbortController | null>(null);

    useEffect(() => {
        const initSupabase = async () => {
            try {
                setDbLoading(true);
                setError('');

                if (!EntitlementsService.isConfigured()) {
                    throw new Error('Supabase is not configured. Please set REACT_APP_SUPABASE_URL and REACT_APP_SUPABASE_ANON_KEY environment variables.');
                }

                const isConnected = await EntitlementsService.testConnection();
                if (!isConnected) {
                    throw new Error('Failed to connect to Supabase. Please check your configuration.');
                }

                const versions = await EntitlementsService.getVersions(selectedPlatform);
                console.log(`Available ${selectedPlatform} versions:`, versions);
                setVersions(versions);
            } catch (error) {
                const errorWithMessage = toErrorWithMessage(error);
                console.error('Failed to initialize database:', errorWithMessage);
                setError(`Failed to initialize database: ${errorWithMessage.message}`);
            } finally {
                setDbLoading(false);
            }
        };

        initSupabase();
    }, [selectedPlatform]);

    // Update versions when platform changes
    useEffect(() => {
        const updateVersions = async () => {
            if (!EntitlementsService.isConfigured()) return;

            try {
                setDbLoading(true);
                const versions = await EntitlementsService.getVersions(selectedPlatform);
                setVersions(versions);
                setSelectedVersion(''); // Reset version selection when platform changes
            } catch (error) {
                console.error('Failed to load versions:', error);
            } finally {
                setDbLoading(false);
            }
        };

        updateVersions();
    }, [selectedPlatform]);

    // Detect mobile viewport
    useEffect(() => {
        const checkMobile = () => {
            setIsMobile(window.innerWidth <= 768);
        };

        checkMobile();
        window.addEventListener('resize', checkMobile);
        return () => window.removeEventListener('resize', checkMobile);
    }, []);

    // Cleanup on unmount
    useEffect(() => {
        return () => {
            if (abortControllerRef.current) {
                abortControllerRef.current.abort();
            }
        };
    }, []);

    const performSearch = useCallback(async (query: string, version: string, type: 'key' | 'file', pathFilter: string = '') => {
        if (!query.trim()) {
            setResults([]);
            setError('');
            setHasSearched(false);
            return;
        }

        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
        }

        abortControllerRef.current = new AbortController();

        try {
            setLoading(true);
            setError('');

            const effectivePathFilter = pathFilter || selectedExecutablePath;

            console.log('Performing search:', { query, version, type, effectivePathFilter });

            let searchResults: EntitlementResult[];
            if (type === 'key') {
                searchResults = await EntitlementsService.searchByKey(
                    query,
                    version || undefined,
                    effectivePathFilter || undefined,
                    200,
                    undefined,
                    selectedPlatform
                );
            } else {
                searchResults = await EntitlementsService.searchByFile(
                    query,
                    version || undefined,
                    effectivePathFilter || undefined,
                    200,
                    undefined,
                    selectedPlatform
                );
            }

            console.log('Search results:', searchResults);

            setResults(searchResults);
            setHasSearched(true);

            // Auto-collapse filters after successful search to give more space for results
            if (searchResults.length > 0) {
                setFiltersOpen(false);
            }

            // Extract unique executable paths for the filter dropdown
            if (type === 'key' && searchResults.length > 0) {
                const paths = Array.from(new Set(searchResults.map(r => r.file_path))).sort();
                setAvailableExecutablePaths(paths);
            }
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                console.log('Search aborted');
                return;
            }

            const errorWithMessage = toErrorWithMessage(error);
            console.error('Search failed:', errorWithMessage);
            setError(`Search failed: ${errorWithMessage.message}`);
            setResults([]);
            setHasSearched(true);
        } finally {
            setLoading(false);
        }
    }, [selectedExecutablePath, selectedPlatform]);

    const debouncedSearch = useMemo(
        () => debounce((query: string, version: string, type: 'key' | 'file', pathFilter: string) => {
            performSearch(query, version, type, pathFilter);
        }, 500),
        [performSearch]
    );

    // Cleanup debounced function on unmount
    useEffect(() => {
        return () => {
            if (debouncedSearch.cancel) {
                debouncedSearch.cancel();
            }
        };
    }, [debouncedSearch]);

    const handleSearchInput = useCallback((value: string) => {
        setSearchQuery(value);
        if (value.trim()) {
            debouncedSearch(value, selectedVersion, searchType, selectedExecutablePath);
        } else {
            setResults([]);
            setHasSearched(false);
            setError('');
        }
    }, [debouncedSearch, selectedVersion, searchType, selectedExecutablePath]);

    const handleSearch = useCallback(() => {
        if (searchQuery.trim()) {
            performSearch(searchQuery, selectedVersion, searchType, selectedExecutablePath);
        }
    }, [performSearch, searchQuery, selectedVersion, searchType, selectedExecutablePath]);

    const handleVersionChange = useCallback((value: string) => {
        const newVersion = value === 'all' ? '' : value;
        setSelectedVersion(newVersion);
        if (searchQuery.trim()) {
            debouncedSearch(searchQuery, newVersion, searchType, selectedExecutablePath);
        }
    }, [debouncedSearch, searchQuery, searchType, selectedExecutablePath]);

    const handlePlatformChange = useCallback((value: string) => {
        setSelectedPlatform(value);
        setSelectedVersion('');
        setResults([]);
        setHasSearched(false);
        setError('');
        setSelectedExecutablePath('');
        setAvailableExecutablePaths([]);
        // TODO: Load versions for the selected platform
        // For now, we'll keep the existing iOS versions
    }, []);

    const handleExecutablePathChange = useCallback((value: string) => {
        const newPath = value === 'all' ? '' : value;
        setSelectedExecutablePath(newPath);
        if (searchQuery.trim()) {
            debouncedSearch(searchQuery, selectedVersion, searchType, newPath);
        }
    }, [debouncedSearch, searchQuery, selectedVersion, searchType]);

    const handleSearchTypeChange = useCallback((type: 'key' | 'file') => {
        setSearchType(type);
        setResults([]);
        setHasSearched(false);
        setError('');
        setSelectedExecutablePath('');
        setAvailableExecutablePaths([]);
        if (searchQuery.trim()) {
            debouncedSearch(searchQuery, selectedVersion, type, '');
        }
    }, [debouncedSearch, searchQuery, selectedVersion]);

    const sortedVersions = useMemo(() => {
        return sortVersions(versions);
    }, [versions]);

    const globalMetadata = useMemo(() => {
        if (results.length === 0) return null;

        const uniqueVersions = new Set(results.map(r => r.version)).size;
        const uniqueFiles = new Set(results.map(r => r.file_path)).size;

        return { uniqueVersions, uniqueFiles };
    }, [results]);

    const formatValue = useCallback((result: EntitlementResult): FormattedValue | null => {
        let value: any;
        let type: FormattedValue['type'] = 'unknown';

        // Extract the actual value based on the value_type
        switch (result.value_type) {
            case 'bool':
                value = result.bool_value;
                type = 'bool';
                break;
            case 'number':
                value = result.number_value;
                type = 'number';
                break;
            case 'string':
                value = result.string_value;
                type = 'string';
                break;
            case 'array':
                try {
                    value = result.array_value ? JSON.parse(result.array_value) : [];
                    type = 'array';
                } catch {
                    value = result.array_value || '';
                    type = 'string';
                }
                break;
            case 'dict':
            case 'object':
                try {
                    value = result.dict_value ? JSON.parse(result.dict_value) : {};
                    type = 'dict';
                } catch {
                    value = result.dict_value || '';
                    type = 'string';
                }
                break;
            default:
                value = result.string_value || result.array_value || result.dict_value || '';
                type = 'string';
        }

        // Generate display string
        const display = formatEntitlementValue(value, result.value_type);

        return {
            type,
            value,
            display
        };
    }, []);

    const renderValue = (valueData: FormattedValue) => {
        switch (valueData.type) {
            case 'bool':
                return (
                    <div className="mt-3">
                        <span className={cn("bool-badge", valueData.value ? "bool-true" : "bool-false")}>
                            {valueData.value ? 'TRUE' : 'FALSE'}
                        </span>
                    </div>
                );
            case 'array':
                if (Array.isArray(valueData.value) && valueData.value.length > 0) {
                    return (
                        <div className="array-container mt-3">
                            {valueData.value.map((item, idx) => (
                                <div key={idx} className="array-item">
                                    <div className="array-bullet"></div>
                                    <span className="text-sm font-mono">{String(item)}</span>
                                </div>
                            ))}
                        </div>
                    );
                }
                break;
            case 'dict':
                if (typeof valueData.value === 'object' && valueData.value !== null) {
                    return (
                        <div className="dict-container mt-3">
                            {Object.entries(valueData.value).map(([key, val], idx) => (
                                <div key={idx} className="dict-entry">
                                    <span className="dict-key">{key}:</span>
                                    <span className="dict-value">{String(val)}</span>
                                </div>
                            ))}
                        </div>
                    );
                }
                break;
            default:
                return (
                    <div className="code-value mt-3">
                        <code>{valueData.display}</code>
                    </div>
                );
        }
    };

    return (
        <Layout title="Entitlements">
            <div className="min-h-screen flex flex-col" style={{ backgroundColor: 'var(--ifm-background-color)' }}>
                <div className="container mx-auto px-4 py-8 flex-1 flex flex-col">
                    {/* Header */}
                    <div className="text-center mb-8">
                        <div className="flex items-center justify-center gap-3 mb-4">
                            <div className="p-3 rounded-lg" style={{ backgroundColor: 'var(--ifm-background-color)' }}>
                                <Database className="h-8 w-8" style={{ color: 'var(--ifm-color-primary)' }} />
                            </div>
                            <h1 className="text-4xl font-bold" style={{ color: 'var(--ifm-color-primary)' }}>
                                Entitlements Browser
                            </h1>
                        </div>

                    </div>

                    {/* Loading State */}
                    {dbLoading && (
                        <div className="mb-6 p-6 rounded-lg border" style={{
                            backgroundColor: 'var(--ifm-background-surface-color)',
                            borderColor: 'var(--ifm-color-emphasis-300)'
                        }}>
                            <div className="flex items-center gap-4">
                                <Loader2 className="animate-spin h-5 w-5" style={{ color: 'var(--ifm-color-primary)' }} />
                                <div>
                                    <p className="font-medium" style={{ color: 'var(--ifm-color-content)' }}>Connecting to database...</p>
                                    <p className="text-sm" style={{ color: 'var(--ifm-color-content-secondary)' }}>Please wait while we establish the connection.</p>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Error State */}
                    {error && !dbLoading && (
                        <div className="mb-6 p-6 rounded-lg border" style={{
                            backgroundColor: 'var(--ifm-color-danger-contrast-background)',
                            borderColor: 'var(--ifm-color-danger)'
                        }}>
                            <div className="flex items-start gap-4">
                                <AlertCircle className="flex-shrink-0 h-5 w-5 mt-0.5" style={{ color: 'var(--ifm-color-danger)' }} />
                                <div className="space-y-2">
                                    <p className="font-medium" style={{ color: 'var(--ifm-color-danger)' }}>Database Error</p>
                                    <p className="text-sm" style={{ color: 'var(--ifm-color-content)' }}>{error}</p>

                                        {error.includes('Database is not configured') && (
                                            <div className="mt-4 p-4 rounded-md border" style={{
                                                backgroundColor: 'var(--ifm-background-surface-color)',
                                                borderColor: 'var(--ifm-color-emphasis-300)'
                                            }}>
                                                <p className="font-medium mb-2" style={{ color: 'var(--ifm-color-content)' }}>Setup Instructions:</p>
                                                <ol className="text-sm space-y-1 list-decimal list-inside" style={{ color: 'var(--ifm-color-content)' }}>
                                                    <li>Create a Supabase project at <a href="https://supabase.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--ifm-color-primary)' }} className="hover:underline">supabase.com</a></li>
                                                    <li>Run the schema from <code className="px-1 py-0.5 rounded" style={{ backgroundColor: 'var(--ifm-color-emphasis-200)' }}>supabase/schema.sql</code> in your Supabase SQL editor</li>
                                                    <li>Generate data using: <code className="px-1 py-0.5 rounded" style={{ backgroundColor: 'var(--ifm-color-emphasis-200)' }}>ipsw ent --pg-host db.your-project.supabase.co --pg-user postgres --pg-password your-password --pg-database postgres --ipsw your-file.ipsw</code></li>
                                                    <li>Set environment variables: <code className="px-1 py-0.5 rounded" style={{ backgroundColor: 'var(--ifm-color-emphasis-200)' }}>REACT_APP_SUPABASE_URL</code> and <code className="px-1 py-0.5 rounded" style={{ backgroundColor: 'var(--ifm-color-emphasis-200)' }}>REACT_APP_SUPABASE_ANON_KEY</code></li>
                                                </ol>
                                                <p className="mt-2 text-sm" style={{ color: 'var(--ifm-color-content-secondary)' }}>See <code className="px-1 py-0.5 rounded" style={{ backgroundColor: 'var(--ifm-color-emphasis-200)' }}>README-SUPABASE.md</code> for detailed instructions.</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                        </div>
                    )}

                    {/* Search Interface */}
                    {!dbLoading && !error && (
                        <div className="space-y-6 flex-1 flex flex-col">
                            {/* Search Filters */}
                            <div className="rounded-lg border" style={{
                                backgroundColor: 'var(--ifm-background-surface-color)',
                                borderColor: 'var(--ifm-color-emphasis-300)'
                            }}>
                                <Collapsible open={filtersOpen} onOpenChange={setFiltersOpen}>
                                    <CollapsibleTrigger asChild>
                                        <div className="cursor-pointer p-6 transition-colors hover:bg-opacity-50" style={{
                                            backgroundColor: filtersOpen ? 'transparent' : 'transparent'
                                        }} onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'var(--ifm-color-emphasis-100)'}
                                           onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}>
                                            <div className="flex items-center justify-between">
                                                <div className="flex items-center gap-3">
                                                    <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--ifm-background-surface-color)' }}>
                                                        <Filter className="h-5 w-5" style={{ color: 'var(--ifm-color-primary)' }} />
                                                    </div>
                                                    <div>
                                                        <h3 className="text-lg font-semibold" style={{ color: 'var(--ifm-color-content)' }}>Search & Filters</h3>
                                                        <p className="text-sm" style={{ color: 'var(--ifm-color-content-secondary)' }}>
                                                            {filtersOpen ? 'Configure your search parameters and filters' : 'Click to modify search and filters'}
                                                        </p>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    {hasSearched && !filtersOpen && (
                                                        <div className="flex items-center gap-2">
                                                            {results.length > 0 && (
                                                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border" style={{
                                                                    borderColor: 'var(--ifm-color-success)',
                                                                    backgroundColor: 'var(--ifm-color-success-contrast-background)',
                                                                    color: 'var(--ifm-color-success)'
                                                                }}>
                                                                    {results.length} result{results.length === 1 ? '' : 's'}
                                                                </span>
                                                            )}
                                                            {searchQuery && (
                                                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-mono border" style={{
                                                                    borderColor: 'var(--ifm-color-emphasis-300)',
                                                                    backgroundColor: 'transparent',
                                                                    color: 'var(--ifm-color-content)'
                                                                }}>
                                                                    "{searchQuery}"
                                                                </span>
                                                            )}
                                                            {selectedPlatform !== 'iOS' && (
                                                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs border" style={{
                                                                    borderColor: 'var(--ifm-color-emphasis-300)',
                                                                    backgroundColor: 'transparent',
                                                                    color: 'var(--ifm-color-content)'
                                                                }}>
                                                                    {selectedPlatform}
                                                                </span>
                                                            )}
                                                            {selectedVersion && (
                                                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs border" style={{
                                                                    borderColor: 'var(--ifm-color-emphasis-300)',
                                                                    backgroundColor: 'transparent',
                                                                    color: 'var(--ifm-color-content)'
                                                                }}>
                                                                    {selectedPlatform} {selectedVersion}
                                                                </span>
                                                            )}
                                                            {selectedExecutablePath && (
                                                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs border" style={{
                                                                    borderColor: 'var(--ifm-color-emphasis-300)',
                                                                    backgroundColor: 'transparent',
                                                                    color: 'var(--ifm-color-content)'
                                                                }}>
                                                                    {selectedExecutablePath.split('/').pop()}
                                                                </span>
                                                            )}
                                                        </div>
                                                    )}
                                                    {filtersOpen ? <ChevronUp className="h-4 w-4" style={{ color: 'var(--ifm-color-content-secondary)' }} /> : <ChevronDown className="h-4 w-4" style={{ color: 'var(--ifm-color-content-secondary)' }} />}
                                                </div>
                                            </div>
                                        </div>
                                    </CollapsibleTrigger>
                                    <CollapsibleContent>
                                        <div className="px-6 pb-6 space-y-6">
                                            {/* Main Filters Row */}
                                            <div className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-5 gap-4">
                                                {/* Platform Filter */}
                                                <div className="space-y-2">
                                                    <label className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--ifm-color-content)' }}>
                                                        <Database className="h-4 w-4" style={{ color: 'var(--ifm-color-content-secondary)' }} />
                                                        Platform
                                                    </label>
                                                    <Select value={selectedPlatform} onValueChange={handlePlatformChange}>
                                                        <SelectTrigger>
                                                            <SelectValue placeholder="Select platform" />
                                                        </SelectTrigger>
                                                        <SelectContent className="select-content">
                                                            {availablePlatforms.map(platform => (
                                                                <SelectItem key={platform} value={platform}>
                                                                    {platform}
                                                                </SelectItem>
                                                            ))}
                                                        </SelectContent>
                                                    </Select>
                                                </div>

                                                {/* Version Filter */}
                                                <div className="space-y-2">
                                                    <label className="text-sm font-medium flex items-center gap-2" style={{ color: 'var(--ifm-color-content)' }}>
                                                        <Smartphone className="h-4 w-4" style={{ color: 'var(--ifm-color-content-secondary)' }} />
                                                        Version Filter
                                                    </label>
                                                    <Select value={selectedVersion || 'all'} onValueChange={handleVersionChange}>
                                                        <SelectTrigger>
                                                            <SelectValue placeholder="All versions" />
                                                        </SelectTrigger>
                                                        <SelectContent className="select-content">
                                                            <SelectItem value="all">All versions</SelectItem>
                                                            {sortedVersions.map(version => (
                                                                <SelectItem key={version} value={version}>
                                                                    {selectedPlatform} {version}
                                                                </SelectItem>
                                                            ))}
                                                        </SelectContent>
                                                    </Select>
                                                </div>

                                                {/* Search Type Selection */}
                                                <div className="space-y-2">
                                                    <label className="text-sm font-medium" style={{ color: 'var(--ifm-color-content)' }}>Search Type</label>
                                                    <div className="flex gap-1">
                                                        <button
                                                            onClick={() => handleSearchTypeChange('key')}
                                                            className="flex items-center gap-1 px-3 py-2 rounded-md text-xs font-medium transition-colors"
                                                            style={{
                                                                backgroundColor: searchType === 'key' ? 'var(--ifm-color-primary)' : 'transparent',
                                                                color: searchType === 'key' ? 'var(--ifm-color-primary-contrast-foreground)' : 'var(--ifm-color-content)',
                                                                border: `1px solid ${searchType === 'key' ? 'var(--ifm-color-primary)' : 'var(--ifm-color-emphasis-300)'}`
                                                            }}
                                                        >
                                                            <Code className="h-3 w-3" />
                                                            Key
                                                        </button>
                                                        <button
                                                            onClick={() => handleSearchTypeChange('file')}
                                                            className="flex items-center gap-1 px-3 py-2 rounded-md text-xs font-medium transition-colors"
                                                            style={{
                                                                backgroundColor: searchType === 'file' ? 'var(--ifm-color-primary)' : 'transparent',
                                                                color: searchType === 'file' ? 'var(--ifm-color-primary-contrast-foreground)' : 'var(--ifm-color-content)',
                                                                border: `1px solid ${searchType === 'file' ? 'var(--ifm-color-primary)' : 'var(--ifm-color-emphasis-300)'}`
                                                            }}
                                                        >
                                                            <FileText className="h-3 w-3" />
                                                            File
                                                        </button>
                                                    </div>
                                                </div>

                                                {/* Executable Path Filter */}
                                                {(availableExecutablePaths.length > 1 || selectedExecutablePath) && (
                                                    <div className="space-y-2">
                                                        <label className="text-sm font-medium" style={{ color: 'var(--ifm-color-content)' }}>Executable Filter</label>
                                                        <Select value={selectedExecutablePath || 'all'} onValueChange={handleExecutablePathChange}>
                                                            <SelectTrigger>
                                                                <SelectValue placeholder={
                                                                    availableExecutablePaths.length > 0
                                                                        ? `All executables (${availableExecutablePaths.length})`
                                                                        : 'All executables'
                                                                } />
                                                            </SelectTrigger>
                                                            <SelectContent className="select-content">
                                                                <SelectItem value="all">
                                                                    {availableExecutablePaths.length > 0
                                                                        ? `All executables (${availableExecutablePaths.length})`
                                                                        : 'All executables'
                                                                    }
                                                                </SelectItem>
                                                                {(() => {
                                                                    return availableExecutablePaths.map(path => {
                                                                        const basename = path.split('/').pop() || path;
                                                                        const displayName = path.length > 50 ?
                                                                            `${basename} - ${path.substring(0, 47)}...` :
                                                                            `${basename} - ${path}`;

                                                                        return (
                                                                            <SelectItem key={path} value={path}>
                                                                                {displayName}
                                                                            </SelectItem>
                                                                        );
                                                                    });
                                                                })()}
                                                            </SelectContent>
                                                        </Select>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Search Input */}
                                            <div className="space-y-2">
                                                <label className="text-sm font-medium" style={{ color: 'var(--ifm-color-content)' }}>
                                                    Search {searchType === 'key' ? 'Entitlement Keys' : 'Executable Paths'}
                                                </label>
                                                <div className="flex gap-2">
                                                    <div className="relative flex-1">
                                                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4" style={{ color: 'var(--ifm-color-content-secondary)' }} />
                                                        <input
                                                            value={searchQuery}
                                                            onChange={(e) => handleSearchInput(e.target.value)}
                                                            placeholder={searchType === 'key'
                                                                ? 'Enter entitlement key (e.g., com.apple.security.app-sandbox)'
                                                                : 'Enter executable name (e.g., WebContent, Safari)'
                                                            }
                                                            className="w-full pl-10 pr-3 py-2 font-mono text-sm rounded-md border transition-colors"
                                                            style={{
                                                                backgroundColor: 'var(--ifm-background-color)',
                                                                borderColor: 'var(--ifm-color-emphasis-300)',
                                                                color: 'var(--ifm-color-content)'
                                                            }}
                                                            disabled={loading}
                                                            onKeyDown={(e) => {
                                                                if (e.key === 'Enter' && !loading && searchQuery.trim()) {
                                                                    handleSearch();
                                                                }
                                                            }}
                                                        />
                                                    </div>
                                                    <button
                                                        onClick={handleSearch}
                                                        disabled={loading || !searchQuery.trim()}
                                                        className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors"
                                                        style={{
                                                            backgroundColor: (loading || !searchQuery.trim()) ? 'var(--ifm-color-emphasis-300)' : 'var(--ifm-color-primary)',
                                                            color: (loading || !searchQuery.trim()) ? 'var(--ifm-color-content-secondary)' : 'var(--ifm-color-primary-contrast-foreground)',
                                                            border: 'none'
                                                        }}
                                                    >
                                                        {loading ? (
                                                            <Loader2 className="h-4 w-4 animate-spin" />
                                                        ) : (
                                                            <Search className="h-4 w-4" />
                                                        )}
                                                        {loading ? 'Searching...' : 'Search'}
                                                    </button>
                                                </div>
                                            </div>

                                            {/* No Results Warning */}
                                            {!loading && hasSearched && searchQuery.trim() && results.length === 0 && (
                                                <div className="p-4 rounded-md border" style={{
                                                    backgroundColor: 'var(--ifm-color-warning-contrast-background)',
                                                    borderColor: 'var(--ifm-color-warning)'
                                                }}>
                                                    <div className="flex items-start gap-3">
                                                        <AlertCircle className="flex-shrink-0 h-5 w-5 mt-0.5" style={{ color: 'var(--ifm-color-warning)' }} />
                                                        <div>
                                                            <p className="font-medium" style={{ color: 'var(--ifm-color-warning-dark)' }}>
                                                                No entitlements found for "{searchQuery}"
                                                                {selectedVersion && ` in ${selectedPlatform} ${selectedVersion}`}
                                                                {selectedExecutablePath && ` in ${selectedExecutablePath}`}
                                                            </p>
                                                            <p className="text-sm mt-1" style={{ color: 'var(--ifm-color-warning-dark)', opacity: 0.8 }}>
                                                                Try adjusting your search terms or filters
                                                            </p>
                                                        </div>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </CollapsibleContent>
                                </Collapsible>
                            </div>

                            {/* Results */}
                            {results.length > 0 && (
                                <div className="space-y-4 flex-1 min-h-0">
                                    {/* Results Header - Only show when filters are expanded */}
                                    {filtersOpen && (
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <h3 className="text-xl font-semibold" style={{ color: 'var(--ifm-color-success)' }}>
                                                    Found {results.length} result{results.length === 1 ? '' : 's'}
                                                </h3>
                                                {globalMetadata && (
                                                    <p className="text-sm" style={{ color: 'var(--ifm-color-content-secondary)' }}>
                                                        {globalMetadata.uniqueVersions > 1 && `${globalMetadata.uniqueVersions} iOS versions • `}
                                                        {globalMetadata.uniqueFiles} unique files
                                                    </p>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {/* Global Metadata */}
                                    {(selectedVersion || (selectedExecutablePath && searchType === 'key')) && results.length > 0 && (
                                        <div className="p-4 rounded-lg" style={{
                                            backgroundColor: 'var(--ifm-color-emphasis-100)',
                                            border: `1px solid var(--ifm-color-emphasis-200)`
                                        }}>
                                            <div className="flex items-center gap-4 text-sm">
                                                <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full border" style={{
                                                    borderColor: 'var(--ifm-color-emphasis-300)',
                                                    backgroundColor: 'transparent',
                                                    color: 'var(--ifm-color-content)'
                                                }}>
                                                    <Smartphone className="h-3 w-3" />
                                                    {selectedPlatform} {results[0].version} ({results[0].build_id})
                                                </span>
                                                {results[0].device_list && (
                                                    <span style={{ color: 'var(--ifm-color-content-secondary)' }}>
                                                        {results[0].device_list}
                                                    </span>
                                                )}
                                                {selectedExecutablePath && searchType === 'key' && (
                                                    <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full border" style={{
                                                        borderColor: 'var(--ifm-color-emphasis-300)',
                                                        backgroundColor: 'transparent',
                                                        color: 'var(--ifm-color-content)'
                                                    }}>
                                                        <FileText className="h-3 w-3" />
                                                        {selectedExecutablePath.split('/').pop()}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {/* Results List */}
                                    <ScrollArea className="flex-1 w-full">
                                        <div className="space-y-3 pr-4">
                                            {results.map((result, idx) => {
                                                const valueData = formatValue(result);
                                                const showMetadata = !selectedVersion;
                                                const allSamePath = searchType === 'file' && results.every(r => r.file_path === results[0].file_path);
                                                const showFilePath = !selectedExecutablePath && !allSamePath;

                                                return (
                                                    <div key={idx} className="animate-fade-in-up p-6 rounded-lg border" style={{
                                                        backgroundColor: 'var(--ifm-background-surface-color)',
                                                        borderColor: 'var(--ifm-color-emphasis-300)'
                                                    }}>
                                                        <div className="space-y-3">
                                                            {/* Main Content */}
                                                            <div className="flex items-start justify-between gap-4">
                                                                <div className="flex-1 min-w-0">
                                                                    <div className="flex items-center gap-2 mb-1">
                                                                        <code
                                                                            className="text-sm font-mono font-medium break-all"
                                                                            style={{ color: 'var(--ifm-color-primary)' }}
                                                                            dangerouslySetInnerHTML={{
                                                                                __html: highlightSearchTerm(result.key, searchQuery)
                                                                            }}
                                                                        />
                                                                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs border" style={{
                                                                            borderColor: 'var(--ifm-color-emphasis-300)',
                                                                            backgroundColor: 'transparent',
                                                                            color: 'var(--ifm-color-content-secondary)'
                                                                        }}>
                                                                            {result.value_type}
                                                                        </span>
                                                                    </div>

                                                                        {showFilePath && (
                                                                            <p className="text-sm font-mono break-all" style={{ color: 'var(--ifm-color-content-secondary)' }}>
                                                                                <span
                                                                                    dangerouslySetInnerHTML={{
                                                                                        __html: highlightSearchTerm(result.file_path, searchQuery)
                                                                                    }}
                                                                                />
                                                                            </p>
                                                                        )}

                                                                        {showMetadata && (
                                                                            <div className="flex items-center gap-2 mt-2">
                                                                                <span className="inline-flex items-center px-2 py-1 rounded-full text-xs" style={{
                                                                                    backgroundColor: 'var(--ifm-color-emphasis-200)',
                                                                                    color: 'var(--ifm-color-content)'
                                                                                }}>
                                                                                    {selectedPlatform} {result.version} ({result.build_id})
                                                                                </span>
                                                                                {result.device_list && (
                                                                                    <span className="text-xs" style={{ color: 'var(--ifm-color-content-secondary)' }}>
                                                                                        {result.device_list}
                                                                                    </span>
                                                                                )}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                </div>

                                                                {/* Value Display */}
                                                                {valueData && valueData.display && (
                                                                    <div className="mt-3">
                                                                        {renderValue(valueData)}
                                                                    </div>
                                                                )}
                                                            </div>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </ScrollArea>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </Layout>
    );
}
