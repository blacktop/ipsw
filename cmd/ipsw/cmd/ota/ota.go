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
package ota

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var colorMode = colors.HiBlue().SprintFunc()
var colorModTime = colors.Faint().SprintFunc()
var colorSize = colors.HiCyan().SprintFunc()
var colorName = colors.Bold().SprintFunc()
var colorLink = colors.HiMagenta().SprintFunc()

// GetAEAKey looks up the AEA decryption key from the JSON database based on OTA filename
func GetAEAKey(otaPath, keyDBPath string) (string, error) {
	if keyDBPath == "" {
		return "", nil
	}

	if otaPath == "" {
		return "", fmt.Errorf("otaPath cannot be empty")
	}

	// Get the base filename (with or without .aea/.zip extension)
	otaFilename := filepath.Base(otaPath)
	otaFilename = strings.TrimSuffix(otaFilename, filepath.Ext(otaFilename))

	// filepath.Base("") returns ".", which is not a valid lookup key
	if otaFilename == "" || otaFilename == "." {
		return "", fmt.Errorf("invalid OTA path: %s", otaPath)
	}

	// Read the key database JSON
	data, err := os.ReadFile(keyDBPath)
	if err != nil {
		return "", fmt.Errorf("failed to read AEA key database: %v", err)
	}

	var entries []types.AEAKeyEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return "", fmt.Errorf("failed to parse AEA key database: %v", err)
	}

	// Build map for O(1) lookup by filename (without extension)
	entryMap := make(map[string]types.AEAKeyEntry, len(entries))
	for _, entry := range entries {
		baseName := strings.TrimSuffix(entry.Filename, filepath.Ext(entry.Filename))
		entryMap[baseName] = entry
	}

	// Look up key by filename
	if entry, ok := entryMap[otaFilename]; ok {
		log.WithFields(log.Fields{
			"os":      entry.OS,
			"version": entry.Version,
			"build":   entry.Build,
		}).Debug("Found AEA key in database")
		return entry.Key, nil
	}

	return "", fmt.Errorf("no AEA key found in database for OTA: %s", otaFilename)
}

// ResolveAEAKey resolves the AEA decryption key using the priority chain:
// keyDBPath → symmetricKey → filename embedded key → automatic AEA metadata lookup
// Returns an ota.Config ready to be used with ota.Open
//
// Parameters can be empty strings to skip that resolution method:
//   - keyDBPath: path to ota_fcs_keys.json database (or empty to skip)
//   - symmetricKey: base64 encoded key (or empty to skip)
//   - insecure: allow insecure connections for automatic key lookup
func ResolveAEAKey(otaPath, keyDBPath, symmetricKey string, insecure bool) *ota.Config {
	conf := &ota.Config{
		SymmetricKey: symmetricKey,
		Insecure:     insecure,
	}

	// Try key database first (highest priority after explicit key)
	if keyDBPath != "" {
		if dbKey, err := GetAEAKey(otaPath, keyDBPath); err == nil && dbKey != "" {
			conf.SymmetricKey = dbKey
			log.Debug("Using AEA key from database")
		} else if err != nil {
			log.WithError(err).Warn("Failed to lookup key in database")
		}
	}

	if conf.SymmetricKey == "" {
		log.Debug("No key provided, will attempt automatic lookup from AEA metadata if OTA is encrypted")
	}

	return conf
}

// ResolveAEAKeyFromFlags resolves AEA key using viper flags (for CLI commands)
func ResolveAEAKeyFromFlags(otaPath string) *ota.Config {
	return ResolveAEAKey(
		otaPath,
		viper.GetString("ota.key-db"),
		viper.GetString("ota.key-val"),
		viper.GetBool("ota.insecure"),
	)
}

func init() {
	OtaCmd.PersistentFlags().String("key-val", "", "Base64 encoded AEA symmetric encryption key")
	OtaCmd.PersistentFlags().String("key-db", "", "Path to AEA keys JSON database (auto-lookup by filename)")
	OtaCmd.MarkFlagFilename("key-db", "json")
	OtaCmd.PersistentFlags().Bool("insecure", false, "Allow insecure connections when fetching AEA keys")
	viper.BindPFlag("ota.key-val", OtaCmd.PersistentFlags().Lookup("key-val"))
	viper.BindPFlag("ota.key-db", OtaCmd.PersistentFlags().Lookup("key-db"))
	viper.BindPFlag("ota.insecure", OtaCmd.PersistentFlags().Lookup("insecure"))
}

// OtaCmd represents the ota command
var OtaCmd = &cobra.Command{
	Use:   "ota",
	Short: "Parse OTAs",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
