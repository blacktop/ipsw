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
package img3

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img3"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img3Cmd.AddCommand(img3ExtractCmd)

	img3ExtractCmd.Flags().StringP("output", "o", "", "Output file for extracted data")
	img3ExtractCmd.MarkFlagFilename("output")
	img3ExtractCmd.Flags().StringP("iv-key", "k", "", "IV+Key for direct decryption (concatenated hex string)")
	img3ExtractCmd.Flags().StringP("iv", "", "", "IV for decryption (hex string)")
	img3ExtractCmd.Flags().StringP("key", "", "", "Key for decryption (hex string)")
	img3ExtractCmd.Flags().BoolP("raw", "r", false, "Extract raw data (no decryption)")
	viper.BindPFlag("img3.extract.output", img3ExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img3.extract.iv-key", img3ExtractCmd.Flags().Lookup("iv-key"))
	viper.BindPFlag("img3.extract.iv", img3ExtractCmd.Flags().Lookup("iv"))
	viper.BindPFlag("img3.extract.key", img3ExtractCmd.Flags().Lookup("key"))
	viper.BindPFlag("img3.extract.raw", img3ExtractCmd.Flags().Lookup("raw"))
}

// img3ExtractCmd represents the extract command
var img3ExtractCmd = &cobra.Command{
	Use:           "extract",
	Short:         "Extract data from img3 files",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		outputFile := viper.GetString("output")
		ivKeyStr := viper.GetString("iv-key")
		ivStr := viper.GetString("iv")
		keyStr := viper.GetString("key")
		rawExtract := viper.GetBool("raw")
		// validate flags
		decrypt := ivKeyStr != "" || (ivStr != "" && keyStr != "")
		if rawExtract && decrypt {
			return fmt.Errorf("cannot use --raw with decryption flags")
		}

		infile := filepath.Clean(args[0])

		data, err := os.ReadFile(infile)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", infile, err)
		}

		if outputFile == "" {
			if rawExtract {
				outputFile = strings.TrimSuffix(infile, ".img3") + ".raw"
				if !strings.HasSuffix(infile, ".img3") {
					outputFile = infile + ".raw"
				}
			} else if decrypt {
				outputFile = strings.TrimSuffix(infile, ".img3") + ".decrypted"
				if !strings.HasSuffix(infile, ".img3") {
					outputFile = infile + ".decrypted"
				}
			} else {
				outputFile = strings.TrimSuffix(infile, ".img3") + ".payload"
				if !strings.HasSuffix(infile, ".img3") {
					outputFile = infile + ".payload"
				}
			}
		}

		if decrypt {
			var iv, key []byte

			if ivKeyStr != "" {
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

				iv = ivBytes
				key = keyBytes
			}

			log.Debugf("Using IV: %x", iv)
			log.Debugf("Using Key: %x", key)

			// Decrypt the IMG3 data directly
			decryptedData, err := img3.Decrypt(data, iv, key)
			if err != nil {
				return fmt.Errorf("failed to decrypt IMG3 data: %v", err)
			}

			if err := os.WriteFile(outputFile, decryptedData, 0644); err != nil {
				return fmt.Errorf("failed to write decrypted data to %s: %v", outputFile, err)
			}

			log.WithFields(log.Fields{
				"path": outputFile,
				"size": humanize.Bytes(uint64(len(decryptedData))),
			}).Debug("Decrypted IMG3 data")

			return nil
		}

		if rawExtract {
			log.WithFields(log.Fields{
				"path": outputFile,
				"size": humanize.Bytes(uint64(len(data))),
			}).Info("Extracting raw IMG3 data")

			if err := os.WriteFile(outputFile, data, 0644); err != nil {
				return fmt.Errorf("failed to write raw data to %s: %v", outputFile, err)
			}

			return nil
		}

		img3File, err := img3.ParseImg3(data)
		if err != nil {
			return fmt.Errorf("failed to parse img3 file %s: %v", infile, err)
		}

		payloadData, err := img3File.GetDataTag()
		if err != nil {
			return fmt.Errorf("failed to get data tag from img3 file %s: %v", infile, err)
		}

		if err := os.WriteFile(outputFile, payloadData, 0644); err != nil {
			return fmt.Errorf("failed to write payload data to %s: %v", outputFile, err)
		}

		log.WithFields(log.Fields{
			"path": outputFile,
			"size": humanize.Bytes(uint64(len(payloadData))),
		}).Info("Payload Data Extracted")

		return nil
	},
}
