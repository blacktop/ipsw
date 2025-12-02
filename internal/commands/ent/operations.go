package ent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/dustin/go-humanize"
)

var colorBin = colors.BoldHiMagenta().SprintFunc()
var colorKey = colors.BoldHiGreen().SprintFunc()
var colorValue = colors.BoldHiBlue().SprintFunc()
var colorVersion = colors.BoldCyan().SprintFunc()

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
func CreatePostgreSQLDatabase(host, port, user, password, database, sslMode, poolMode string, ipsws, inputs []string) error {
	// Create PostgreSQL database connection
	dbConn, err := db.NewPostgresWithSSL(host, port, user, password, database, sslMode, poolMode, 1000)
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
func SearchPostgreSQLEntitlements(host, port, user, password, database, sslMode, poolMode, keyPattern, valuePattern, filePattern, versionFilter string, fileOnly bool, limit int) error {
	// Create database connection
	dbConn, err := db.NewPostgresWithSSL(host, port, user, password, database, sslMode, poolMode, 1000)
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
func ShowPostgreSQLStatistics(host, port, user, password, database, sslMode, poolMode string) error {
	dbConn, err := db.NewPostgresWithSSL(host, port, user, password, database, sslMode, poolMode, 1000)
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

// CreateSQLiteDatabaseWithReplacement creates or updates SQLite database with replacement support
func CreateSQLiteDatabaseWithReplacement(dbPath string, ipsws, inputs []string, replaceStrategy string, dryRun bool) error {
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
	strategy := NewSQLiteReplacementStrategy(dbService)

	return processIPSWsWithReplacement(strategy, ipsws, inputs, replaceStrategy, dryRun)
}

// CreatePostgreSQLDatabaseWithReplacement creates or updates PostgreSQL database with replacement support
func CreatePostgreSQLDatabaseWithReplacement(host, port, user, password, database, sslMode, poolMode string, ipsws, inputs []string, replaceStrategy string, dryRun bool) error {
	// Create PostgreSQL database connection
	dbConn, err := db.NewPostgresWithSSL(host, port, user, password, database, sslMode, poolMode, 1000)
	if err != nil {
		return fmt.Errorf("failed to create PostgreSQL database connection: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL database: %v", err)
	}
	defer dbConn.Close()

	dbService := NewDatabaseService(dbConn)
	strategy := NewPostgreSQLReplacementStrategy(dbService)

	return processIPSWsWithReplacement(strategy, ipsws, inputs, replaceStrategy, dryRun)
}

// processIPSWsWithReplacement processes IPSWs with replacement logic
func processIPSWsWithReplacement(strategy ReplacementStrategy, ipsws, inputs []string, replaceStrategy string, dryRun bool) error {
	config := &ReplacementConfig{
		Strategy: replaceStrategy,
		DryRun:   dryRun,
	}

	// Process IPSWs
	for _, ipswPath := range ipsws {
		log.WithField("ipsw", filepath.Base(ipswPath)).Info("Processing IPSW")

		// Parse IPSW info for version comparison
		ipswInfo, err := info.Parse(ipswPath)
		if err != nil {
			return fmt.Errorf("failed to parse IPSW info from %s: %v", ipswPath, err)
		}

		// Detect platform for replacement logic
		platform := DetectPlatformFromIPSW(ipswPath, ipswInfo)
		newIPSW := IPSWInfo{
			ID:       generateIPSWIDWithPlatform(platform, ipswInfo.Plists.BuildManifest.ProductVersion, ipswInfo.Plists.BuildManifest.ProductBuildVersion),
			Name:     filepath.Base(ipswPath),
			Version:  ipswInfo.Plists.BuildManifest.ProductVersion,
			BuildID:  ipswInfo.Plists.BuildManifest.ProductBuildVersion,
			Platform: string(platform),
		}

		// Get existing IPSWs for comparison (platform-aware)
		existingIPSWs, err := strategy.GetExistingIPSWs(string(platform), newIPSW.Version)
		if err != nil {
			return fmt.Errorf("failed to get existing IPSWs: %v", err)
		}

		// Create replacement plan
		plan, err := strategy.CreateReplacementPlan(newIPSW, existingIPSWs, config)
		if err != nil {
			return fmt.Errorf("failed to create replacement plan: %v", err)
		}

		// Execute replacement if needed
		if len(plan.ToReplace) > 0 || config.DryRun {
			if err := strategy.ExecuteReplacement(plan); err != nil {
				return fmt.Errorf("failed to execute replacement: %v", err)
			}
		}

		// Extract and store entitlements (only if not dry run and plan was executed)
		if !config.DryRun {
			// Extract entitlements from IPSW
			entDB, err := GetDatabase(&Config{
				IPSW:     ipswPath,
				Database: "", // Don't create blob file
			})
			if err != nil {
				return fmt.Errorf("failed to extract entitlements from %s: %v", ipswPath, err)
			}

			// Store entitlements using the strategy's database service
			sqliteStrat, ok := strategy.(*SQLiteReplacementStrategy)
			if ok {
				if err := sqliteStrat.service.StoreEntitlements(ipswPath, entDB); err != nil {
					return fmt.Errorf("failed to store entitlements: %v", err)
				}
			} else if pgStrat, ok := strategy.(*PostgreSQLReplacementStrategy); ok {
				if err := pgStrat.service.StoreEntitlements(ipswPath, entDB); err != nil {
					return fmt.Errorf("failed to store entitlements: %v", err)
				}
			}
		}
	}

	// Process input folders if specified
	for _, inputPath := range inputs {
		log.WithField("input", inputPath).Info("Processing input folder")
		// For inputs, we don't have version info so we use legacy replacement
		// This would need to be implemented based on your input processing logic
		return fmt.Errorf("input folder processing with replacement not yet implemented")
	}

	if !dryRun {
		fmt.Printf("✓ Database creation/update completed successfully\n")
	}

	return nil
}
