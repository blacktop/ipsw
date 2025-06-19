/*
Copyright © 2025 blacktop

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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img3"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(img3Cmd)
	img3Cmd.Flags().StringP("iv-key", "k", "", "IV+Key for direct decryption (concatenated hex string)")
	img3Cmd.Flags().StringP("iv", "", "", "IV for decryption (hex string)")
	img3Cmd.Flags().StringP("key", "", "", "Key for decryption (hex string)")
	img3Cmd.Flags().StringP("output", "o", "", "Output file for decrypted data")
}

// img3Cmd represents the img3 command
var img3Cmd = &cobra.Command{
	Use:           "img3",
	Short:         "Parse and optionally decrypt img3 files",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		ivKeyStr, _ := cmd.Flags().GetString("iv-key")
		ivStr, _ := cmd.Flags().GetString("iv")
		keyStr, _ := cmd.Flags().GetString("key")
		outputFile, _ := cmd.Flags().GetString("output")

		infile := filepath.Clean(args[0])

		data, err := os.ReadFile(infile)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", infile, err)
		}

		img3File, err := img3.ParseImg3(data)
		if err != nil {
			return fmt.Errorf("failed to parse img3 file %s: %v", infile, err)
		}

		fmt.Println(img3File)

		// validate flags for decryption
		methodCount := 0
		if ivKeyStr != "" {
			methodCount++
		}
		if ivStr != "" || keyStr != "" {
			methodCount++
			// If one is specified, both must be specified
			if ivStr == "" || keyStr == "" {
				return fmt.Errorf("both --iv and --key must be specified together")
			}
		}
		if methodCount > 1 {
			return fmt.Errorf("cannot specify more than one decryption method (--iv-key, --iv and --key)")
		}
		if methodCount == 0 {
			// No decryption requested, just parse and display
			return nil
		}

		var iv, key []byte

		if ivKeyStr != "" {
			log.Info("Attempting direct decryption with provided IV+Key...")

			ivKeyStr = strings.ReplaceAll(ivKeyStr, " ", "")
			ivKeyStr = strings.ReplaceAll(ivKeyStr, ":", "")

			ivKeyBytes, err := hex.DecodeString(ivKeyStr)
			if err != nil {
				return fmt.Errorf("failed to decode IV+Key hex string: %v", err)
			}

			if len(ivKeyBytes) < 32 {
				return fmt.Errorf("IV+Key must be at least 32 bytes (64 hex characters), got %d bytes", len(ivKeyBytes))
			}

			iv = ivKeyBytes[:16]
			key = ivKeyBytes[16:]

			if len(key) != 16 && len(key) != 24 && len(key) != 32 {
				return fmt.Errorf("key must be 16, 24, or 32 bytes, got %d bytes", len(key))
			}
		} else if ivStr != "" && keyStr != "" {
			log.Info("Attempting direct decryption with provided IV and Key...")

			ivStr := strings.ReplaceAll(ivStr, " ", "")
			ivBytes, err := hex.DecodeString(ivStr)
			if err != nil {
				return fmt.Errorf("failed to decode IV hex string: %v", err)
			}

			keyStr := strings.ReplaceAll(keyStr, " ", "")
			keyBytes, err := hex.DecodeString(keyStr)
			if err != nil {
				return fmt.Errorf("failed to decode Key hex string: %v", err)
			}

			if len(ivBytes) != 16 {
				return fmt.Errorf("IV must be exactly 16 bytes (32 hex characters), got %d bytes", len(ivBytes))
			}

			if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
				return fmt.Errorf("key must be 16, 24, or 32 bytes (32, 48, or 64 hex characters), got %d bytes", len(keyBytes))
			}
		}

		log.Debugf("Using IV: %x", iv)
		log.Debugf("Using Key: %x", key)

		// Decrypt the IMG3 data directly
		decryptedData, err := img3.Decrypt(data, iv, key)
		if err != nil {
			return fmt.Errorf("failed to decrypt IMG3 data: %v", err)
		}

		log.Infof("Successfully decrypted %d bytes", len(decryptedData))

		if outputFile == "" {
			outputFile = strings.TrimSuffix(infile, ".img3") + ".decrypted"
			if !strings.HasSuffix(infile, ".img3") {
				outputFile = infile + ".decrypted"
			}
		}

		if err := os.WriteFile(outputFile, decryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write decrypted data to %s: %v", outputFile, err)
		}

		log.Infof("Decrypted data written to: %s", outputFile)

		return nil
	},
}
