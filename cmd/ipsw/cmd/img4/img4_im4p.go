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
package img4

import (
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4Im4pCmd)

	// Add subcommands to im4p
	img4Im4pCmd.AddCommand(img4Im4pInfoCmd)
	img4Im4pCmd.AddCommand(img4Im4pExtractCmd)
	img4Im4pCmd.AddCommand(img4Im4pCreateCmd)

	// Info command flags
	img4Im4pInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4pInfoCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.info.json", img4Im4pInfoCmd.Flags().Lookup("json"))

	// Extract command flags
	img4Im4pExtractCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pExtractCmd.Flags().BoolP("extra", "e", false, "Extract extra data")
	img4Im4pExtractCmd.Flags().BoolP("kbag", "b", false, "Extract keybags as JSON")
	img4Im4pExtractCmd.Flags().String("iv-key", "", "AES iv+key for decryption")
	img4Im4pExtractCmd.Flags().StringP("iv", "i", "", "AES iv for decryption")
	img4Im4pExtractCmd.Flags().StringP("key", "k", "", "AES key for decryption")
	img4Im4pExtractCmd.MarkFlagFilename("output")
	img4Im4pExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.extract.extra", img4Im4pExtractCmd.Flags().Lookup("extra"))
	viper.BindPFlag("img4.im4p.extract.kbag", img4Im4pExtractCmd.Flags().Lookup("kbag"))
	viper.BindPFlag("img4.im4p.extract.output", img4Im4pExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4p.extract.iv-key", img4Im4pExtractCmd.Flags().Lookup("iv-key"))
	viper.BindPFlag("img4.im4p.extract.iv", img4Im4pExtractCmd.Flags().Lookup("iv"))
	viper.BindPFlag("img4.im4p.extract.key", img4Im4pExtractCmd.Flags().Lookup("key"))

	// Create command flags
	img4Im4pCreateCmd.Flags().StringP("type", "t", "", "Type string (required)")
	img4Im4pCreateCmd.Flags().StringP("version", "v", "", "Version string")
	img4Im4pCreateCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4pCreateCmd.Flags().StringP("compress", "c", "none", fmt.Sprintf("Compress payload (%s)", strings.Join(img4.CompressionTypes, ", ")))
	img4Im4pCreateCmd.RegisterFlagCompletionFunc("compress", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return img4.CompressionTypes, cobra.ShellCompDirectiveDefault
	})
	img4Im4pCreateCmd.Flags().StringP("extra", "e", "", "Extra data file to append")
	img4Im4pCreateCmd.MarkFlagRequired("type")
	img4Im4pCreateCmd.MarkFlagFilename("output")
	img4Im4pCreateCmd.MarkFlagFilename("extra")
	img4Im4pCreateCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.create.type", img4Im4pCreateCmd.Flags().Lookup("type"))
	viper.BindPFlag("img4.im4p.create.version", img4Im4pCreateCmd.Flags().Lookup("version"))
	viper.BindPFlag("img4.im4p.create.output", img4Im4pCreateCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4p.create.compress", img4Im4pCreateCmd.Flags().Lookup("compress"))
	viper.BindPFlag("img4.im4p.create.extra", img4Im4pCreateCmd.Flags().Lookup("extra"))
}

// img4Im4pCmd represents the im4p command group
var img4Im4pCmd = &cobra.Command{
	Use:   "im4p",
	Short: "IM4P payload operations",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4pInfoCmd represents the im4p info command
var img4Im4pInfoCmd = &cobra.Command{
	Use:           "info <IM4P>",
	Short:         "Display detailed IM4P information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		im4p, err := img4.OpenPayload(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}

		if viper.GetBool("img4.im4p.info.json") {
			jsonData, err := json.MarshalIndent(im4p, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal IM4P info: %v", err)
			}
			fmt.Println(string(jsonData))
		} else {
			fmt.Println(im4p)
		}

		return nil
	},
}

// img4Im4pExtractCmd represents the im4p extract command
var img4Im4pExtractCmd = &cobra.Command{
	Use:           "extract <IM4P>",
	Short:         "Extract IM4P data",
	Long:          "Extract IM4P payload data or extra metadata.",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		filePath := filepath.Clean(args[0])
		// flags
		outputPath := viper.GetString("img4.im4p.extract.output")
		extractExtra := viper.GetBool("img4.im4p.extract.extra")
		extractKbag := viper.GetBool("img4.im4p.extract.kbag")
		ivkeyStr := viper.GetString("img4.im4p.extract.iv-key")
		ivStr := viper.GetString("img4.im4p.extract.iv")
		keyStr := viper.GetString("img4.im4p.extract.key")
		// validate flags
		if extractExtra && extractKbag {
			return fmt.Errorf("cannot specify both --extra and --kbag")
		}
		// Check if decryption is requested
		decrypt := len(ivkeyStr) != 0 || len(ivStr) != 0 || len(keyStr) != 0
		if decrypt {
			if extractExtra {
				return fmt.Errorf("cannot use --extra with decryption")
			}
			if len(ivkeyStr) != 0 && (len(ivStr) != 0 || len(keyStr) != 0) {
				return fmt.Errorf("cannot specify both --iv-key AND --iv/--key")
			} else if len(ivkeyStr) == 0 && (len(ivStr) == 0 && len(keyStr) == 0) {
				return fmt.Errorf("must specify either --iv-key OR --iv AND --key")
			}
		}

		if outputPath == "" {
			baseName := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
			if extractExtra {
				outputPath = baseName + ".extra"
			} else if decrypt {
				outputPath = baseName + ".dec"
			} else {
				outputPath = baseName + ".payload"
			}
		}

		im4p, err := img4.OpenPayload(filePath)
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}

		if extractKbag {
			if len(im4p.Keybags) == 0 {
				return fmt.Errorf("no keybags found in IM4P")
			}
			dat, err := json.Marshal(&struct {
				Tag     string        `json:"tag,omitempty"`
				Version string        `json:"version,omitempty"`
				Keybags []img4.Keybag `json:"keybags,omitempty"`
			}{
				Tag:     filepath.Base(args[0]),
				Version: im4p.Version,
				Keybags: im4p.Keybags,
			})
			if err != nil {
				return fmt.Errorf("failed to marshal im4g kbag: %v", err)
			}
			if viper.IsSet("img4.im4p.extract.output") {
				utils.Indent(log.WithFields(log.Fields{
					"path": outputPath,
				}).Info, 2)("Writing keybags JSON to file")
				return os.WriteFile(outputPath, dat, 0644)
			} else {
				fmt.Println(string(dat))
			}
			return nil
		}

		// Handle decryption if requested
		if decrypt {
			if !im4p.Encrypted {
				return fmt.Errorf("cannot decrypt unencrypted IM4P")
			}

			var iv []byte
			var key []byte

			if len(ivkeyStr) != 0 {
				ivkey, err := hex.DecodeString(ivkeyStr)
				if err != nil {
					return fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				iv = ivkey[:aes.BlockSize]
				key = ivkey[aes.BlockSize:]
			} else {
				var err error
				iv, err = hex.DecodeString(ivStr)
				if err != nil {
					return fmt.Errorf("failed to decode --iv: %v", err)
				}
				key, err = hex.DecodeString(keyStr)
				if err != nil {
					return fmt.Errorf("failed to decode --key: %v", err)
				}
			}
			utils.Indent(log.WithFields(log.Fields{
				"path": outputPath,
			}).Info, 2)("Decrypting Payload")
			return img4.DecryptPayload(filePath, outputPath, iv, key)
		}

		if extractExtra {
			if !im4p.HasExtraData() {
				return fmt.Errorf("no extra data found in IM4P file")
			}
			if im4p.Encrypted {
				log.Warn("extracting encrypted IM4P extra data")
			}

			extraData := im4p.GetExtraData()
			if len(extraData) == 0 {
				return fmt.Errorf("extra data is empty")
			}

			utils.Indent(log.WithFields(log.Fields{
				"bytes": len(extraData),
				"path":  outputPath,
			}).Info, 2)("Extracting Extra Data")

			return os.WriteFile(outputPath, extraData, 0644)
		}

		if im4p.Encrypted {
			utils.Indent(log.Warn, 3)("extracting encrypted IM4P payload")
		}

		payloadData, err := im4p.GetData()
		if err != nil {
			return fmt.Errorf("failed to get payload data: %v", err)
		}

		if len(payloadData) == 0 {
			return fmt.Errorf("payload data is empty")
		}

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
		}).Info, 2)("Extracting Payload")

		return os.WriteFile(outputPath, payloadData, 0644)
	},
}

// img4Im4pCreateCmd represents the im4p create command
var img4Im4pCreateCmd = &cobra.Command{
	Use:           "create <input-file>",
	Short:         "Create IM4P payload from raw data",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		inputPath := filepath.Clean(args[0])

		// flags
		typ := viper.GetString("img4.im4p.create.type")
		version := viper.GetString("img4.im4p.create.version")
		outputPath := viper.GetString("img4.im4p.create.output")
		compressionType := viper.GetString("img4.im4p.create.compress")
		extraPath := viper.GetString("img4.im4p.create.extra")
		// validate flags
		if len(typ) != 4 {
			return fmt.Errorf("--type must be exactly 4 characters, got %d: %s", len(typ), typ)
		}
		if outputPath == "" {
			outputPath = filepath.Clean(inputPath) + ".im4p"
		}
		if !slices.Contains(img4.CompressionTypes, compressionType) {
			return fmt.Errorf("unsupported compression type: %s (supported: %s)", compressionType, strings.Join(img4.CompressionTypes, ", "))
		}

		var comp img4.CompressionAlgorithm
		switch strings.ToLower(compressionType) {
		case "lzss":
			comp = img4.CompressionAlgorithmLZSS
		case "lzfse":
			comp = img4.CompressionAlgorithmLZFSE
		case "none", "":
			comp = img4.CompressionAlgorithmMAX // No compression
		}

		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		var extraData []byte
		if len(extraPath) > 0 {
			extraData, err = os.ReadFile(extraPath)
			if err != nil {
				return fmt.Errorf("failed to read extra data file: %v", err)
			}
		}

		im4p, err := img4.CreatePayload(&img4.CreatePayloadConfig{
			Type:        typ,
			Version:     version,
			Data:        data,
			ExtraData:   extraData,
			Compression: comp,
			// TODO: add keybags support for IM4P creation
			Keybags: nil,
		})
		if err != nil {
			return fmt.Errorf("failed to create IM4P payload: %v", err)
		}

		im4pData, err := im4p.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal IM4P payload: %v", err)
		}

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(im4pData))),
		}).Info, 2)("Creating IM4P")

		if err := os.WriteFile(outputPath, im4pData, 0644); err != nil {
			return fmt.Errorf("failed to write IM4P file: %v", err)
		}

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(im4pData))),
		}).Info, 2)("Created IM4P")

		return nil
	},
}
