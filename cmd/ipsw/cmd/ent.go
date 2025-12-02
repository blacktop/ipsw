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

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(entCmd)

	// Input flags
	entCmd.Flags().StringArray("ipsw", []string{}, "IPSWs to process")
	entCmd.Flags().StringArray("input", []string{}, "Folders of MachOs to analyze")
	entCmd.MarkFlagDirname("input")

	// Database flags
	entCmd.Flags().String("sqlite", "", "Path to SQLite database")

	// PostgreSQL flags
	entCmd.Flags().String("pg-host", "", "PostgreSQL host")
	entCmd.Flags().String("pg-port", "5432", "PostgreSQL port")
	entCmd.Flags().String("pg-user", "", "PostgreSQL user")
	entCmd.Flags().String("pg-password", "", "PostgreSQL password")
	entCmd.Flags().String("pg-database", "", "PostgreSQL database name")
	entCmd.Flags().String("pg-sslmode", "require", "PostgreSQL SSL mode (disable, require, verify-ca, verify-full)")
	entCmd.Flags().String("pg-poolmode", "", "PostgreSQL pool mode (session, transaction, statement, or empty for no pooling)")

	// Search flags
	entCmd.Flags().StringP("key", "k", "", "Search for entitlement key pattern")
	entCmd.Flags().StringP("value", "v", "", "Search for entitlement value pattern")
	entCmd.Flags().StringP("file", "f", "", "Search for file path pattern")
	entCmd.Flags().String("version", "", "Filter by iOS version")

	// Output flags
	entCmd.Flags().Bool("file-only", false, "Only output file paths")
	entCmd.Flags().Bool("stats", false, "Show database statistics")
	entCmd.Flags().Int("limit", 100, "Limit number of results")

	// Replacement flags
	entCmd.Flags().Bool("replace", false, "Replace older builds of the same iOS version with newer builds")
	entCmd.Flags().String("replace-strategy", "auto", "Replacement strategy: auto, prompt, force")
	entCmd.Flags().Bool("dry-run", false, "Show what would be replaced without making changes")

	// Viper bindings
	viper.BindPFlag("ent.ipsw", entCmd.Flags().Lookup("ipsw"))
	viper.BindPFlag("ent.input", entCmd.Flags().Lookup("input"))
	viper.BindPFlag("ent.sqlite", entCmd.Flags().Lookup("sqlite"))
	viper.BindPFlag("ent.pg-host", entCmd.Flags().Lookup("pg-host"))
	viper.BindPFlag("ent.pg-port", entCmd.Flags().Lookup("pg-port"))
	viper.BindPFlag("ent.pg-user", entCmd.Flags().Lookup("pg-user"))
	viper.BindPFlag("ent.pg-password", entCmd.Flags().Lookup("pg-password"))
	viper.BindPFlag("ent.pg-database", entCmd.Flags().Lookup("pg-database"))
	viper.BindPFlag("ent.pg-sslmode", entCmd.Flags().Lookup("pg-sslmode"))
	viper.BindPFlag("ent.pg-poolmode", entCmd.Flags().Lookup("pg-poolmode"))
	viper.BindPFlag("ent.key", entCmd.Flags().Lookup("key"))
	viper.BindPFlag("ent.value", entCmd.Flags().Lookup("value"))
	viper.BindPFlag("ent.file", entCmd.Flags().Lookup("file"))
	viper.BindPFlag("ent.version", entCmd.Flags().Lookup("version"))
	viper.BindPFlag("ent.file-only", entCmd.Flags().Lookup("file-only"))
	viper.BindPFlag("ent.stats", entCmd.Flags().Lookup("stats"))
	viper.BindPFlag("ent.limit", entCmd.Flags().Lookup("limit"))
	viper.BindPFlag("ent.replace", entCmd.Flags().Lookup("replace"))
	viper.BindPFlag("ent.replace-strategy", entCmd.Flags().Lookup("replace-strategy"))
	viper.BindPFlag("ent.dry-run", entCmd.Flags().Lookup("dry-run"))

}

// entCmd represents the ent command
var entCmd = &cobra.Command{
	Use:   "ent",
	Short: "Manage and search entitlements database",
	Example: heredoc.Doc(`
		# Create SQLite database from IPSW
		❯ ipsw ent --sqlite entitlements.db --ipsw iPhone16,1_18.2_22C150_Restore.ipsw

		# Create database from multiple IPSWs
		❯ ipsw ent --sqlite entitlements.db --ipsw *.ipsw

		# Create PostgreSQL database from IPSW (for Supabase)
		❯ ipsw ent --pg-host db.xyz.supabase.co --pg-user postgres --pg-password your-password --pg-database postgres --ipsw iPhone16,1_18.2_22C150_Restore.ipsw

		# Search for entitlement key
		❯ ipsw ent --sqlite entitlements.db --key platform-application

		# Search for entitlement value
		❯ ipsw ent --sqlite entitlements.db --value LockdownMode

		# Search for specific file
		❯ ipsw ent --sqlite entitlements.db --file WebContent

		# Filter by iOS version and search
		❯ ipsw ent --sqlite entitlements.db --version 18.2 --key sandbox

		# Show database statistics
		❯ ipsw ent --sqlite entitlements.db --stats

		# Search PostgreSQL database (Supabase)
		❯ ipsw ent --pg-host db.xyz.supabase.co --pg-user postgres --pg-password your-password --pg-database postgres --key sandbox
		
		# Replace older iOS builds with newer ones
		❯ ipsw ent --sqlite entitlements.db --ipsw iPhone16,1_26.0_22G87_Restore.ipsw --replace
		
		# Preview what would be replaced
		❯ ipsw ent --sqlite entitlements.db --ipsw iPhone16,1_26.0_22G87_Restore.ipsw --replace --dry-run`),
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// Get flags
		ipsws := viper.GetStringSlice("ent.ipsw")
		inputs := viper.GetStringSlice("ent.input")
		sqliteDB := viper.GetString("ent.sqlite")
		pgHost := viper.GetString("ent.pg-host")
		pgPort := viper.GetString("ent.pg-port")
		pgUser := viper.GetString("ent.pg-user")
		pgPassword := viper.GetString("ent.pg-password")
		pgDatabase := viper.GetString("ent.pg-database")
		pgSSLMode := viper.GetString("ent.pg-sslmode")
		pgPoolMode := viper.GetString("ent.pg-poolmode")
		keyPattern := viper.GetString("ent.key")
		valuePattern := viper.GetString("ent.value")
		filePattern := viper.GetString("ent.file")
		versionFilter := viper.GetString("ent.version")
		fileOnly := viper.GetBool("ent.file-only")
		showStats := viper.GetBool("ent.stats")
		limit := viper.GetInt("ent.limit")
		replace := viper.GetBool("ent.replace")
		replaceStrategy := viper.GetString("ent.replace-strategy")
		dryRun := viper.GetBool("ent.dry-run")

		// Validate required flags
		if sqliteDB == "" && pgHost == "" {
			return fmt.Errorf("either --sqlite (SQLite) or --pg-host (PostgreSQL) is required")
		}

		// Validate mutually exclusive flags (works for CLI, ENV, and config values)
		if sqliteDB != "" && pgHost != "" {
			return fmt.Errorf("--sqlite and --pg-host are mutually exclusive")
		}

		if len(ipsws) > 0 && len(inputs) > 0 {
			return fmt.Errorf("--ipsw and --input are mutually exclusive")
		}

		// Count search/operation flags
		searchOpCount := 0
		if keyPattern != "" {
			searchOpCount++
		}
		if valuePattern != "" {
			searchOpCount++
		}
		if filePattern != "" {
			searchOpCount++
		}
		if showStats {
			searchOpCount++
		}
		if searchOpCount > 1 {
			return fmt.Errorf("--key, --value, --file, and --stats are mutually exclusive")
		}

		// Validate replacement flags
		if replace && (keyPattern != "" || valuePattern != "" || filePattern != "" || showStats) {
			return fmt.Errorf("--replace cannot be used with search operations")
		}

		if replaceStrategy != "auto" && replaceStrategy != "prompt" && replaceStrategy != "force" {
			return fmt.Errorf("--replace-strategy must be one of: auto, prompt, force")
		}

		if dryRun && !replace {
			return fmt.Errorf("--dry-run can only be used with --replace")
		}

		// Validate PostgreSQL flags if using PostgreSQL
		if pgHost != "" {
			if pgUser == "" || pgDatabase == "" {
				return fmt.Errorf("--pg-user and --pg-database are required when using PostgreSQL")
			}
		}

		// For SQLite searches, database file must exist
		if sqliteDB != "" {
			if finfo, err := os.Stat(sqliteDB); os.IsExist(err) {
				if finfo.IsDir() {
					return fmt.Errorf("database path %s is a directory, not a file", sqliteDB)
				}
			}
		}

		// Handle database creation
		if len(ipsws) > 0 || len(inputs) > 0 {
			if pgHost != "" {
				if replace {
					return ent.CreatePostgreSQLDatabaseWithReplacement(pgHost, pgPort, pgUser, pgPassword, pgDatabase, pgSSLMode, pgPoolMode, ipsws, inputs, replaceStrategy, dryRun)
				}
				return ent.CreatePostgreSQLDatabase(pgHost, pgPort, pgUser, pgPassword, pgDatabase, pgSSLMode, pgPoolMode, ipsws, inputs)
			}
			if replace {
				return ent.CreateSQLiteDatabaseWithReplacement(sqliteDB, ipsws, inputs, replaceStrategy, dryRun)
			}
			return ent.CreateSQLiteDatabase(sqliteDB, ipsws, inputs)
		}

		if showStats {
			if pgHost != "" {
				return ent.ShowPostgreSQLStatistics(pgHost, pgPort, pgUser, pgPassword, pgDatabase, pgSSLMode, pgPoolMode)
			}
			return ent.ShowSQLiteStatistics(sqliteDB)
		}

		// Perform search
		if pgHost != "" {
			return ent.SearchPostgreSQLEntitlements(pgHost, pgPort, pgUser, pgPassword, pgDatabase, pgSSLMode, pgPoolMode, keyPattern, valuePattern, filePattern, versionFilter, fileOnly, limit)
		}
		return ent.SearchSQLiteEntitlements(sqliteDB, keyPattern, valuePattern, filePattern, versionFilter, fileOnly, limit)
	},
}
