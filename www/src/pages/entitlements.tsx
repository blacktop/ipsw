import React, { useState, useEffect } from 'react';
import Layout from '@theme/Layout';
import { createDbWorker } from 'sql.js-httpvfs';

export default function Entitlements() {
    const [dbWorker, setDbWorker] = useState<any>(null);
    const [key, setKey] = useState<string>('');
    const [results, setResults] = useState<string[]>([]);
    const [loading, setLoading] = useState<boolean>(false);
    const [dbLoading, setDbLoading] = useState<boolean>(true);
    const [error, setError] = useState<string>('');

    useEffect(() => {
        const initDb = async () => {
            if (!dbWorker) {
                // Set a timeout to prevent hanging forever
                const timeoutId = setTimeout(() => {
                    setDbLoading(false);
                    setError('Database initialization timed out. The database file may be missing or corrupted.');
                }, 10000); // 10 second timeout

                try {
                    setDbLoading(true);
                    setError('');

                    console.log('Creating database worker...');

                    let worker;
                    try {
                        worker = await createDbWorker(
                            [{
                                from: 'inline',
                                config: {
                                    serverMode: 'full',
                                    requestChunkSize: 4096,
                                    url: './db/ipsw.db'
                                }
                            }],
                            // Use relative paths to the worker files that should be in static folder
                            './sqlite.worker.js',
                            './sql-wasm.wasm'
                        );
                        console.log('Database worker created successfully');
                    } catch (workerError) {
                        console.error('Failed to create database worker:', workerError);
                        clearTimeout(timeoutId);
                        throw new Error(`Failed to load database worker: ${workerError.message}. This usually means the database file is missing or corrupted.`);
                    }

                    // Clear the timeout since we got a response
                    clearTimeout(timeoutId);

                    // Validate database schema
                    try {
                        console.log('Starting database validation...');
                        // Check if required tables exist
                        const tableRes = await (worker.db as any).exec(
                            `SELECT name FROM sqlite_master WHERE type='table';`
                        );

                        // Handle case where database is completely empty or has no results
                        let tables: string[] = [];
                        if (tableRes && tableRes.length > 0 && tableRes[0] && tableRes[0].values) {
                            tables = tableRes[0].values.map((row: any[]) => row[0]);
                        }
                        console.log('Available tables:', tables);

                        if (tables.length === 0) {
                            throw new Error('Database is empty or corrupted. No tables found. Please ensure the database file contains the required entitlement data.');
                        }

                        if (!tables.includes('entitlement_keys')) {
                            throw new Error(`Database schema mismatch. Expected 'entitlement_keys' table but found tables: ${tables.join(', ')}. Please ensure you're using the correct database file.`);
                        }

                        // Check if the entitlement_keys table has the expected columns
                        const schemaRes = await (worker.db as any).exec(
                            `PRAGMA table_info(entitlement_keys);`
                        );

                        let columns: string[] = [];
                        if (schemaRes && schemaRes.length > 0 && schemaRes[0] && schemaRes[0].values) {
                            columns = schemaRes[0].values.map((row: any[]) => row[1]);
                        }
                        console.log('entitlement_keys columns:', columns);

                        const requiredColumns = ['file_path', 'key'];
                        const missingColumns = requiredColumns.filter(col => !columns.includes(col));

                        if (missingColumns.length > 0) {
                            throw new Error(`Database schema mismatch. Missing required columns in 'entitlement_keys' table: ${missingColumns.join(', ')}`);
                        }

                        // Test a simple query to make sure the data format is correct
                        const testRes = await (worker.db as any).exec(
                            `SELECT COUNT(*) FROM entitlement_keys LIMIT 1;`
                        );

                        let count = 0;
                        if (testRes && testRes.length > 0 && testRes[0] && testRes[0].values && testRes[0].values.length > 0) {
                            count = testRes[0].values[0][0] || 0;
                        }
                        console.log('Total entitlement records:', count);

                        if (count === 0) {
                            throw new Error('Database contains no data. No entitlement records found in the entitlement_keys table. Please ensure the database contains entitlement data.');
                        }

                    } catch (validationError) {
                        console.error('Database validation failed:', validationError);
                        throw new Error(`Database validation failed: ${validationError.message}`);
                    }

                    setDbWorker(worker);
                } catch (err) {
                    console.error('Failed to initialize database:', err);
                    clearTimeout(timeoutId); // Clear timeout on error
                    setError(`Failed to initialize database: ${err.message}`);
                } finally {
                    setDbLoading(false);
                }
            }
        };
        initDb();
    }, [dbWorker]);

    const handleSearch = async () => {
        if (!dbWorker) {
            setError('Database not initialized yet');
            return;
        }

        try {
            setLoading(true);
            setError('');

            // First, let's check what tables exist in the database
            const tableRes = await (dbWorker.db as any).exec(
                `SELECT name FROM sqlite_master WHERE type='table';`
            );
            console.log('Available tables:', tableRes[0]?.values || []);

            // Try to query the entitlement_keys table
            const res = await (dbWorker.db as any).exec(
                `SELECT DISTINCT file_path FROM entitlement_keys WHERE key LIKE ? LIMIT 100`,
                [`%${key}%`]
            );

            // Handle cases where res is empty or undefined
            let searchResults: string[] = [];
            if (res && res.length > 0 && res[0] && res[0].values) {
                searchResults = res[0].values.map((row: any[]) => row[0]);
            }

            setResults(searchResults);
        } catch (err) {
            console.error('Search failed:', err);
            setError(`Search failed: ${err.message}`);
            setResults([]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Layout title="Entitlements">
            <div style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto' }}>
                <div style={{ marginBottom: '2rem' }}>
                    <h1 style={{ marginBottom: '0.5rem', color: '#2e3440' }}>Entitlements Browser</h1>
                    <p style={{ margin: 0, color: '#5e6c84', fontSize: '1.1em' }}>
                        Search for entitlement keys across iOS system files. This database contains entitlement information extracted from iOS system files.
                    </p>
                </div>

                {dbLoading && (
                    <div style={{
                        padding: '1rem',
                        backgroundColor: '#e3f2fd',
                        borderRadius: '8px',
                        marginBottom: '1rem',
                        color: '#1565c0',
                        border: '1px solid #bbdefb',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.5rem'
                    }}>
                        <div style={{
                            width: '16px',
                            height: '16px',
                            borderRadius: '50%',
                            background: 'conic-gradient(#1565c0, #bbdefb, #1565c0)'
                        }}></div>
                        <span>Loading database and validating schema...</span>
                    </div>
                )}

                {error && !dbLoading && (
                    <div style={{
                        padding: '1rem',
                        backgroundColor: '#ffebee',
                        borderRadius: '8px',
                        marginBottom: '1rem',
                        color: '#c62828',
                        border: '1px solid #ffcdd2'
                    }}>
                        <strong>Database Error:</strong> {error}
                        {(error.includes('empty') || error.includes('No tables found') || error.includes('no data')) && (
                            <div style={{
                                marginTop: '1rem',
                                fontSize: '0.9em',
                                backgroundColor: '#fff3e0',
                                color: '#e65100',
                                padding: '0.75rem',
                                borderRadius: '4px',
                                border: '1px solid #ffcc02'
                            }}>
                                <p style={{ margin: '0 0 0.5rem 0', fontWeight: 'bold' }}>📋 To set up the entitlements database:</p>
                                <ol style={{ margin: '0.5rem 0', paddingLeft: '1.5rem' }}>
                                    <li>Use the ipsw CLI tool to extract entitlement data from iOS files</li>
                                    <li>Generate a SQLite database with an <code>entitlement_keys</code> table</li>
                                    <li>Ensure the table has <code>file_path</code> and <code>key</code> columns</li>
                                    <li>Place the database file at <code>www/static/db/ipsw.db</code></li>
                                </ol>
                                <p style={{ margin: '0.5rem 0 0 0', fontSize: '0.85em' }}>
                                    💡 <strong>Tip:</strong> The current database file is {error.includes('No tables found') ? 'empty (0 bytes)' : 'missing required data'}
                                </p>
                            </div>
                        )}
                        {error.includes('schema mismatch') && (
                            <div style={{
                                marginTop: '1rem',
                                fontSize: '0.9em',
                                backgroundColor: '#fff3e0',
                                color: '#e65100',
                                padding: '0.75rem',
                                borderRadius: '4px',
                                border: '1px solid #ffcc02'
                            }}>
                                <p style={{ margin: '0 0 0.5rem 0', fontWeight: 'bold' }}>🔧 Database Schema Issue:</p>
                                <p style={{ margin: '0.5rem 0' }}>
                                    The database file exists but doesn't have the expected structure.
                                    Please verify that your database contains an <code>entitlement_keys</code> table
                                    with <code>file_path</code> and <code>key</code> columns.
                                </p>
                            </div>
                        )}
                    </div>
                )}

                {!dbLoading && !error && dbWorker && (
                    <div style={{
                        backgroundColor: '#f8fffe',
                        border: '1px solid #e0f2f1',
                        borderRadius: '8px',
                        padding: '1.5rem'
                    }}>
                        <div style={{ marginBottom: '1.5rem' }}>
                            <label style={{
                                display: 'block',
                                marginBottom: '0.5rem',
                                fontWeight: '600',
                                color: '#2e3440'
                            }}>
                                Search Entitlement Keys
                            </label>
                            <div style={{ display: 'flex', gap: '0.75rem' }}>
                                <input
                                    type="text"
                                    value={key}
                                    onChange={(e) => setKey(e.target.value)}
                                    placeholder="Enter entitlement key (e.g., com.apple.security.app-sandbox)"
                                    style={{
                                        flex: 1,
                                        padding: '0.875rem 1rem',
                                        fontSize: '1rem',
                                        border: '2px solid #e0e7ff',
                                        borderRadius: '6px',
                                        outline: 'none',
                                        transition: 'border-color 0.2s',
                                        backgroundColor: '#fff'
                                    }}
                                    disabled={loading}
                                    onKeyPress={(e) => {
                                        if (e.key === 'Enter' && !loading && key.trim()) {
                                            handleSearch();
                                        }
                                    }}
                                    onFocus={(e) => (e.currentTarget as HTMLInputElement).style.borderColor = '#3b82f6'}
                                    onBlur={(e) => (e.currentTarget as HTMLInputElement).style.borderColor = '#e0e7ff'}
                                />
                                <button
                                    onClick={handleSearch}
                                    style={{
                                        padding: '0.875rem 1.75rem',
                                        fontSize: '1rem',
                                        backgroundColor: (!loading && key.trim()) ? '#3b82f6' : '#9ca3af',
                                        color: 'white',
                                        border: 'none',
                                        borderRadius: '6px',
                                        cursor: (!loading && key.trim()) ? 'pointer' : 'not-allowed',
                                        fontWeight: '600',
                                        transition: 'background-color 0.2s',
                                        minWidth: '120px'
                                    }}
                                    disabled={loading || !key.trim()}
                                    onMouseEnter={(e) => {
                                        if (!loading && key.trim()) {
                                            (e.currentTarget as HTMLButtonElement).style.backgroundColor = '#2563eb';
                                        }
                                    }}
                                    onMouseLeave={(e) => {
                                        if (!loading && key.trim()) {
                                            (e.currentTarget as HTMLButtonElement).style.backgroundColor = '#3b82f6';
                                        }
                                    }}
                                >
                                    {loading ? 'Searching...' : 'Search'}
                                </button>
                            </div>
                        </div>

                        <div style={{ marginTop: '1.5rem' }}>
                            {results.length > 0 ? (
                                <div>
                                    <h3 style={{
                                        marginBottom: '1rem',
                                        color: '#059669',
                                        fontSize: '1.2em'
                                    }}>
                                        Found {results.length} file{results.length === 1 ? '' : 's'} containing "{key}":
                                    </h3>
                                    <div style={{
                                        backgroundColor: '#fff',
                                        border: '1px solid #e5e7eb',
                                        borderRadius: '8px',
                                        maxHeight: '500px',
                                        overflowY: 'auto',
                                        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)'
                                    }}>
                                        {results.map((path, idx) => (
                                            <div key={idx} style={{
                                                padding: '0.75rem 1.25rem',
                                                borderBottom: idx < results.length - 1 ? '1px solid #f3f4f6' : 'none',
                                                fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                                                fontSize: '0.9em',
                                                color: '#374151',
                                                backgroundColor: idx % 2 === 0 ? '#fafafa' : '#fff',
                                                transition: 'background-color 0.1s',
                                                cursor: 'default'
                                            }}
                                                onMouseEnter={(e) => (e.currentTarget as HTMLDivElement).style.backgroundColor = '#f0f9ff'}
                                                onMouseLeave={(e) => (e.currentTarget as HTMLDivElement).style.backgroundColor = idx % 2 === 0 ? '#fafafa' : '#fff'}
                                            >
                                                {path}
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ) : (
                                key.trim() && !loading && (
                                    <div style={{
                                        padding: '1.25rem',
                                        backgroundColor: '#fffbeb',
                                        border: '1px solid #fbbf24',
                                        borderRadius: '8px',
                                        color: '#92400e'
                                    }}>
                                        <strong>No results found</strong> for "{key}". Try a different search term or check if the database contains this entitlement.
                                    </div>
                                )
                            )}
                        </div>
                    </div>
                )}
            </div>
        </Layout>
    );
} 