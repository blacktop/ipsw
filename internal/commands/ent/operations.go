package ent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
)

var colorBin = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
var colorKey = color.New(color.Bold, color.FgHiGreen).SprintFunc()
var colorValue = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorVersion = color.New(color.Bold, color.FgCyan).SprintFunc()

// CreateSQLiteDatabase creates or updates the SQLite database
func CreateSQLiteDatabase(dbPath string, ipsws, inputs []string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %v", err)
	}

	// Create SQLite database connection
	dbConn, err := db.NewSqlite(dbPath, 1000)
	if err != nil {
		return fmt.Errorf("failed to create SQLite database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %v", err)
	}
	defer dbConn.Close()

	dbService := NewDatabaseService(dbConn)

	// Process IPSWs
	for _, ipswPath := range ipsws {
		log.WithField("ipsw", filepath.Base(ipswPath)).Info("Processing IPSW")

		// Extract entitlements from IPSW
		entDB, err := GetDatabase(&Config{
			IPSW:     ipswPath,
			Database: "", // Don't create blob file
		})
		if err != nil {
			return fmt.Errorf("failed to extract entitlements from %s: %v", ipswPath, err)
		}

		// Store in SQLite database
		if err := dbService.StoreEntitlements(ipswPath, entDB); err != nil {
			return fmt.Errorf("failed to store entitlements for %s: %v", ipswPath, err)
		}

		log.WithField("ipsw", filepath.Base(ipswPath)).Info("Successfully processed")
	}

	// Process input folders
	for _, inputPath := range inputs {
		log.WithField("input", inputPath).Info("Processing folder")

		entDB, err := GetDatabase(&Config{
			Folder:   inputPath,
			Database: "", // Don't create blob file
		})
		if err != nil {
			return fmt.Errorf("failed to extract entitlements from %s: %v", inputPath, err)
		}

		// Store in SQLite database
		if err := dbService.StoreEntitlements("", entDB); err != nil {
			return fmt.Errorf("failed to store entitlements for %s: %v", inputPath, err)
		}

		log.WithField("input", inputPath).Info("Successfully processed")
	}

	log.Info("Database creation/update completed successfully")
	return nil
}

// CreatePostgreSQLDatabase creates or updates the PostgreSQL database
func CreatePostgreSQLDatabase(host, port, user, password, database, sslMode string, ipsws, inputs []string) error {
	// Create PostgreSQL database connection
	dbConn, err := db.NewPostgresWithSSL(host, port, user, password, database, sslMode, 1000)
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL database: %v", err)
	}
	defer dbConn.Close()

	dbService := NewDatabaseService(dbConn)

	// Process IPSWs
	for _, ipswPath := range ipsws {
		log.WithField("ipsw", filepath.Base(ipswPath)).Info("Processing IPSW")

		// Extract entitlements from IPSW
		entDB, err := GetDatabase(&Config{
			IPSW:     ipswPath,
			Database: "", // Don't create blob file
		})
		if err != nil {
			return fmt.Errorf("failed to extract entitlements from %s: %v", ipswPath, err)
		}

		// Store in PostgreSQL database
		if err := dbService.StoreEntitlements(ipswPath, entDB); err != nil {
			return fmt.Errorf("failed to store entitlements for %s: %v", ipswPath, err)
		}

		log.WithField("ipsw", filepath.Base(ipswPath)).Info("Successfully processed")
	}

	// Process input folders
	for _, inputPath := range inputs {
		log.WithField("input", inputPath).Info("Processing folder")

		entDB, err := GetDatabase(&Config{
			Folder:   inputPath,
			Database: "", // Don't create blob file
		})
		if err != nil {
			return fmt.Errorf("failed to extract entitlements from %s: %v", inputPath, err)
		}

		// Store in PostgreSQL database
		if err := dbService.StoreEntitlements("", entDB); err != nil {
			return fmt.Errorf("failed to store entitlements for %s: %v", inputPath, err)
		}

		log.WithField("input", inputPath).Info("Successfully processed")
	}

	log.Info("PostgreSQL database creation/update completed successfully")
	return nil
}

// SearchSQLiteEntitlements searches the SQLite database for entitlements
func SearchSQLiteEntitlements(dbPath, keyPattern, valuePattern, filePattern, versionFilter string, fileOnly bool, limit int) error {
	// Create database connection
	dbConn, err := db.NewSqlite(dbPath, 1000)
	if err != nil {
		return fmt.Errorf("failed to create SQLite database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %v", err)
	}
	defer dbConn.Close()

	return searchEntitlements(dbConn, keyPattern, valuePattern, filePattern, versionFilter, fileOnly, limit)
}

// SearchPostgreSQLEntitlements searches the PostgreSQL database for entitlements
func SearchPostgreSQLEntitlements(host, port, user, password, database, sslMode, keyPattern, valuePattern, filePattern, versionFilter string, fileOnly bool, limit int) error {
	// Create database connection
	dbConn, err := db.NewPostgresWithSSL(host, port, user, password, database, sslMode, 1000)
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL database: %v", err)
	}
	defer dbConn.Close()

	return searchEntitlements(dbConn, keyPattern, valuePattern, filePattern, versionFilter, fileOnly, limit)
}

// searchEntitlements is a common function for searching entitlements
func searchEntitlements(dbConn db.Database, keyPattern, valuePattern, filePattern, versionFilter string, fileOnly bool, limit int) error {
	dbService := NewDatabaseService(dbConn)

	// Use web-optimized search for better performance
	results, err := dbService.SearchEntitlements(versionFilter, keyPattern, filePattern, limit)
	if err != nil {
		return fmt.Errorf("failed to search entitlements: %v", err)
	}

	if len(results) == 0 {
		log.Info("No entitlements found matching criteria")
		return nil
	}

	// Display results
	if !fileOnly {
		log.Infof("Found %d entitlements matching criteria", len(results))
		fmt.Println()
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	for _, result := range results {
		// Extract key, value, and path from related objects
		if result.Key == nil || result.Value == nil || result.Path == nil {
			continue // Skip if relations weren't loaded
		}

		key := result.Key.Key
		value := result.Value.Value
		valueType := result.Value.ValueType
		filePath := result.Path.Path

		// Check value pattern if specified
		if valuePattern != "" {
			if !contains(value, valuePattern) {
				continue
			}
		}

		if fileOnly {
			fmt.Fprintf(w, "%s\n", colorBin(filePath))
		} else {
			version := "unknown"
			buildID := "unknown"
			if result.Ipsw != nil {
				version = result.Ipsw.Version
				buildID = result.Ipsw.BuildID
			}
			fmt.Fprintf(w, "%s\t%s\t[%s %s]\n",
				colorKey(key),
				colorBin(filePath),
				colorVersion(version),
				buildID)

			// Display value based on type
			switch valueType {
			case "string", "bool", "number":
				if value != "" {
					fmt.Fprintf(w, " - %s\n", colorValue(value))
				}
			case "array", "dict":
				if value != "" {
					fmt.Fprintf(w, " - %s\n", colorValue(value))
				}
			}
		}
	}
	w.Flush()

	return nil
}

// ShowSQLiteStatistics displays SQLite database statistics
func ShowSQLiteStatistics(dbPath string) error {
	dbConn, err := db.NewSqlite(dbPath, 1000)
	if err != nil {
		return fmt.Errorf("failed to create SQLite database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %v", err)
	}
	defer dbConn.Close()

	return showDatabaseStatistics(dbConn, "SQLite", func() (int64, error) {
		if fileInfo, err := os.Stat(dbPath); err == nil {
			return fileInfo.Size(), nil
		}
		return 0, nil
	})
}

// ShowPostgreSQLStatistics displays PostgreSQL database statistics
func ShowPostgreSQLStatistics(host, port, user, password, database, sslMode string) error {
	dbConn, err := db.NewPostgresWithSSL(host, port, user, password, database, sslMode, 1000)
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL database: %v", err)
	}
	defer dbConn.Close()

	return showDatabaseStatistics(dbConn, "PostgreSQL", func() (int64, error) {
		return 0, nil // PostgreSQL doesn't have a simple file size
	})
}

// showDatabaseStatistics is a common function for displaying database statistics
func showDatabaseStatistics(dbConn db.Database, dbType string, getSizeFunc func() (int64, error)) error {
	dbService := NewDatabaseService(dbConn)

	stats, err := dbService.GetStatistics()
	if err != nil {
		return fmt.Errorf("failed to get database statistics: %v", err)
	}

	log.Infof("%s Database Statistics", dbType)
	fmt.Printf("\n")
	fmt.Printf("IPSWs:         %d\n", stats["ipsw_count"])
	fmt.Printf("Entitlements:  %d\n", stats["entitlement_mapping_count"])
	fmt.Printf("Unique Keys:   %d\n", stats["unique_key_count"])
	fmt.Printf("Unique Values: %d\n", stats["unique_value_count"])

	if dbType == "SQLite" {
		if fileSize, err := getSizeFunc(); err == nil && fileSize > 0 {
			fmt.Printf("Database Size: %s\n", humanize.Bytes(uint64(fileSize)))
		}
	}
	fmt.Printf("\n")

	// Show available iOS versions
	versions, err := dbService.GetIOSVersions()
	if err == nil && len(versions) > 0 {
		fmt.Printf("Available iOS Versions:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		for _, version := range versions {
			fmt.Fprintf(w, "  %s\n", colorVersion(version))
		}
		w.Flush()
		fmt.Printf("\n")
	}

	if topKeys, ok := stats["top_keys"].([]struct {
		Key   string
		Count int64
	}); ok && len(topKeys) > 0 {
		fmt.Printf("Top 10 Most Common Entitlement Keys:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		for i, key := range topKeys {
			fmt.Fprintf(w, "%d.\t%s\t%d\n", i+1, colorKey(key.Key), key.Count)
		}
		w.Flush()
		fmt.Printf("\n")
	}

	if leastKeys, ok := stats["least_keys"].([]struct {
		Key   string
		Count int64
	}); ok && len(leastKeys) > 0 {
		fmt.Printf("Top 10 Least Common Entitlement Keys (>1 occurrence):\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		for i, key := range leastKeys {
			fmt.Fprintf(w, "%d.\t%s\t%d\n", i+1, colorKey(key.Key), key.Count)
		}
		w.Flush()
	}

	return nil
}

// contains performs case-insensitive substring search
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	if haystack == "" {
		return false
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
