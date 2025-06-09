/*
Copyright © 2018-2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var colorBin = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
var colorKey = color.New(color.Bold, color.FgHiGreen).SprintFunc()
var colorValue = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorVersion = color.New(color.Bold, color.FgCyan).SprintFunc()

func init() {
	rootCmd.AddCommand(entCmd)

	// Input flags
	entCmd.Flags().StringArray("ipsw", []string{}, "IPSWs to process")
	entCmd.Flags().StringArray("input", []string{}, "Folders of MachOs to analyze")
	entCmd.MarkFlagDirname("input")

	// Database flags
	entCmd.Flags().String("db", "", "Path to SQLite database")

	// Search flags
	entCmd.Flags().StringP("key", "k", "", "Search for entitlement key pattern")
	entCmd.Flags().StringP("value", "v", "", "Search for entitlement value pattern")
	entCmd.Flags().StringP("file", "f", "", "Search for file path pattern")
	entCmd.Flags().String("version", "", "Filter by iOS version")

	// Output flags
	entCmd.Flags().Bool("file-only", false, "Only output file paths")
	entCmd.Flags().Bool("stats", false, "Show database statistics")
	entCmd.Flags().Int("limit", 100, "Limit number of results")

	// Viper bindings
	viper.BindPFlag("ent.ipsw", entCmd.Flags().Lookup("ipsw"))
	viper.BindPFlag("ent.input", entCmd.Flags().Lookup("input"))
	viper.BindPFlag("ent.db", entCmd.Flags().Lookup("db"))
	viper.BindPFlag("ent.key", entCmd.Flags().Lookup("key"))
	viper.BindPFlag("ent.value", entCmd.Flags().Lookup("value"))
	viper.BindPFlag("ent.file", entCmd.Flags().Lookup("file"))
	viper.BindPFlag("ent.version", entCmd.Flags().Lookup("version"))
	viper.BindPFlag("ent.file-only", entCmd.Flags().Lookup("file-only"))
	viper.BindPFlag("ent.stats", entCmd.Flags().Lookup("stats"))
	viper.BindPFlag("ent.limit", entCmd.Flags().Lookup("limit"))

	// Mark mutually exclusive flags
	entCmd.MarkFlagsMutuallyExclusive("key", "value", "file", "stats")
	entCmd.MarkFlagsMutuallyExclusive("ipsw", "input")
}

// entCmd represents the ent command
var entCmd = &cobra.Command{
	Use:   "ent",
	Short: "Manage and search entitlements in SQLite database",
	Example: heredoc.Doc(`
		# Create SQLite database from IPSW
		❯ ipsw ent --db entitlements.db --ipsw iPhone16,1_18.2_22C150_Restore.ipsw

		# Create database from multiple IPSWs  
		❯ ipsw ent --db entitlements.db --ipsw *.ipsw

		# Search for entitlement key
		❯ ipsw ent --db entitlements.db --key platform-application

		# Search for entitlement value
		❯ ipsw ent --db entitlements.db --value LockdownMode

		# Search for specific file
		❯ ipsw ent --db entitlements.db --file WebContent

		# Filter by iOS version and search
		❯ ipsw ent --db entitlements.db --version 18.2 --key sandbox

		# Show database statistics
		❯ ipsw ent --db entitlements.db --stats

		# GitHub Action usage (for automation)
		❯ ipsw ent --db www/static/db/ipsw.db --ipsw latest.ipsw`),
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// Get flags
		ipsws := viper.GetStringSlice("ent.ipsw")
		inputs := viper.GetStringSlice("ent.input")
		sqliteDB := viper.GetString("ent.db")
		keyPattern := viper.GetString("ent.key")
		valuePattern := viper.GetString("ent.value")
		filePattern := viper.GetString("ent.file")
		versionFilter := viper.GetString("ent.version")
		fileOnly := viper.GetBool("ent.file-only")
		showStats := viper.GetBool("ent.stats")
		limit := viper.GetInt("ent.limit")

		// Validate required flags
		if sqliteDB == "" {
			return fmt.Errorf("--db is required")
		}

		// For searches, database must exist
		if finfo, err := os.Stat(sqliteDB); os.IsExist(err) {
			if finfo.IsDir() {
				return fmt.Errorf("database path %s is a directory, not a file", sqliteDB)
			}
		}

		// Handle database creation
		if len(ipsws) > 0 || len(inputs) > 0 {
			return createEntitlementDatabase(sqliteDB, ipsws, inputs)
		}

		color.NoColor = viper.GetBool("no-color") || fileOnly

		if showStats {
			return showDatabaseStatistics(sqliteDB)
		}

		// Perform search
		return searchEntitlements(sqliteDB, keyPattern, valuePattern, filePattern, versionFilter, fileOnly, limit)
	},
}

// createEntitlementDatabase creates or updates the SQLite database
func createEntitlementDatabase(dbPath string, ipsws, inputs []string) error {
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

	dbService := ent.NewDatabaseService(dbConn)

	// Process IPSWs
	for _, ipswPath := range ipsws {
		log.WithField("ipsw", filepath.Base(ipswPath)).Info("Processing IPSW")

		// Extract entitlements from IPSW
		entDB, err := ent.GetDatabase(&ent.Config{
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

		entDB, err := ent.GetDatabase(&ent.Config{
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

// searchEntitlements searches the database for entitlements
func searchEntitlements(dbPath, keyPattern, valuePattern, filePattern, versionFilter string, fileOnly bool, limit int) error {
	// Create database connection
	dbConn, err := db.NewSqlite(dbPath, 1000)
	if err != nil {
		return fmt.Errorf("failed to create SQLite database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %v", err)
	}
	defer dbConn.Close()

	dbService := ent.NewDatabaseService(dbConn)

	// Use web-optimized search for better performance
	results, err := dbService.SearchWebEntitlements(versionFilter, keyPattern, filePattern, limit)
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
		// Check value pattern if specified
		if valuePattern != "" {
			found := false
			switch result.ValueType {
			case "string":
				if contains(result.StringValue, valuePattern) {
					found = true
				}
			case "array":
				if contains(result.ArrayValue, valuePattern) {
					found = true
				}
			case "dict":
				if contains(result.DictValue, valuePattern) {
					found = true
				}
			}
			if !found {
				continue
			}
		}

		if fileOnly {
			fmt.Fprintf(w, "%s\n", colorBin(result.FilePath))
		} else {
			fmt.Fprintf(w, "%s\t%s\t[%s %s]\n",
				colorKey(result.Key),
				colorBin(result.FilePath),
				colorVersion(result.IOSVersion),
				result.BuildID)

			// Display value based on type
			switch result.ValueType {
			case "string":
				if result.StringValue != "" {
					fmt.Fprintf(w, " - %s\n", colorValue(result.StringValue))
				}
			case "bool":
				if result.BoolValue != nil {
					fmt.Fprintf(w, " - %s\n", colorValue(fmt.Sprintf("%t", *result.BoolValue)))
				}
			case "number":
				if result.NumberValue != nil {
					fmt.Fprintf(w, " - %s\n", colorValue(fmt.Sprintf("%d", *result.NumberValue)))
				}
			case "array":
				if result.ArrayValue != "" {
					fmt.Fprintf(w, " - %s\n", colorValue(result.ArrayValue))
				}
			case "dict":
				if result.DictValue != "" {
					fmt.Fprintf(w, " - %s\n", colorValue(result.DictValue))
				}
			}
		}
	}
	w.Flush()

	return nil
}

// showDatabaseStatistics displays database statistics
func showDatabaseStatistics(dbPath string) error {
	dbConn, err := db.NewSqlite(dbPath, 1000)
	if err != nil {
		return fmt.Errorf("failed to create SQLite database: %v", err)
	}
	if err := dbConn.Connect(); err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %v", err)
	}
	defer dbConn.Close()

	dbService := ent.NewDatabaseService(dbConn)

	stats, err := dbService.GetStatistics()
	if err != nil {
		return fmt.Errorf("failed to get database statistics: %v", err)
	}

	log.Info("SQLite Database Statistics")
	fmt.Printf("\n")
	fmt.Printf("IPSWs:        %d\n", stats["ipsw_count"])
	fmt.Printf("Entitlements: %d\n", stats["entitlement_count"])
	fmt.Printf("Keys:         %d\n", stats["key_count"])
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
