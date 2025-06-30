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
	"regexp"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
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
	img4Im4pExtractCmd.Flags().BoolP("raw", "r", false, "Extract raw data (compressed/encrypted)")
	img4Im4pExtractCmd.Flags().BoolP("extra", "e", false, "Extract extra data")
	img4Im4pExtractCmd.Flags().BoolP("kbag", "b", false, "Extract keybags as JSON")
	img4Im4pExtractCmd.Flags().String("iv-key", "", "AES iv+key for decryption")
	img4Im4pExtractCmd.Flags().StringP("iv", "i", "", "AES iv for decryption")
	img4Im4pExtractCmd.Flags().StringP("key", "k", "", "AES key for decryption")
	img4Im4pExtractCmd.Flags().Bool("lookup", false, "Auto-lookup IV/key on theapplewiki.com")
	img4Im4pExtractCmd.Flags().String("lookup-device", "", "Device identifier for key lookup (e.g., iPhone14,2)")
	img4Im4pExtractCmd.Flags().String("lookup-build", "", "Build number for key lookup (e.g., 20H71)")
	img4Im4pExtractCmd.MarkFlagFilename("output")
	img4Im4pExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4p.extract.raw", img4Im4pExtractCmd.Flags().Lookup("raw"))
	viper.BindPFlag("img4.im4p.extract.extra", img4Im4pExtractCmd.Flags().Lookup("extra"))
	viper.BindPFlag("img4.im4p.extract.kbag", img4Im4pExtractCmd.Flags().Lookup("kbag"))
	viper.BindPFlag("img4.im4p.extract.output", img4Im4pExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4p.extract.iv-key", img4Im4pExtractCmd.Flags().Lookup("iv-key"))
	viper.BindPFlag("img4.im4p.extract.iv", img4Im4pExtractCmd.Flags().Lookup("iv"))
	viper.BindPFlag("img4.im4p.extract.key", img4Im4pExtractCmd.Flags().Lookup("key"))
	viper.BindPFlag("img4.im4p.extract.lookup", img4Im4pExtractCmd.Flags().Lookup("lookup"))
	viper.BindPFlag("img4.im4p.extract.lookup-device", img4Im4pExtractCmd.Flags().Lookup("lookup-device"))
	viper.BindPFlag("img4.im4p.extract.lookup-build", img4Im4pExtractCmd.Flags().Lookup("lookup-build"))

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
	Use:     "im4p",
	Aliases: []string{"p"},
	Short:   "IM4P payload operations",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4pInfoCmd represents the im4p info command
var img4Im4pInfoCmd = &cobra.Command{
	Use:     "info <IM4P>",
	Aliases: []string{"i"},
	Short:   "Display detailed IM4P information",
	Example: heredoc.Doc(`
		# Display IM4P information
		❯ ipsw img4 im4p info kernelcache.im4p

		# Output as JSON
		❯ ipsw img4 im4p info --json kernelcache.im4p`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		im4p, err := img4.OpenPayload(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}

		if viper.GetBool("img4.im4p.info.json") {
			jsonData, err := json.Marshal(im4p)
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
	Use:     "extract <IM4P>",
	Aliases: []string{"e"},
	Short:   "Extract IM4P data",
	Long:    "Extract IM4P payload data or extra metadata.",
	Example: heredoc.Doc(`
		# Extract decompressed payload data
		❯ ipsw img4 im4p extract kernelcache.im4p

		# Extract extra data (if present)
		❯ ipsw img4 im4p extract --extra kernelcache.im4p

		# Extract keybags as JSON
		❯ ipsw img4 im4p extract --kbag encrypted.im4p

		# Decrypt and extract payload
		❯ ipsw img4 im4p extract --iv 1234... --key 5678... encrypted.im4p

		# Auto-lookup key and decrypt
		❯ ipsw img4 im4p extract --lookup --lookup-device iPhone14,2 --lookup-build 20H71 RestoreRamDisk.im4p

		# Auto-detect device/build from folder structure (e.g., 22F76__iPhone11,8/...)
		❯ ipsw img4 im4p extract --lookup /path/to/22F76__iPhone11,8/sep-firmware.n841.RELEASE.im4p

		# Extract to specific output file
		❯ ipsw img4 im4p extract --output kernel.bin kernelcache.im4p`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// flags
		outputPath := viper.GetString("img4.im4p.extract.output")
		rawExtract := viper.GetBool("img4.im4p.extract.raw")
		extractExtra := viper.GetBool("img4.im4p.extract.extra")
		extractKbag := viper.GetBool("img4.im4p.extract.kbag")
		ivkeyStr := viper.GetString("img4.im4p.extract.iv-key")
		ivStr := viper.GetString("img4.im4p.extract.iv")
		keyStr := viper.GetString("img4.im4p.extract.key")
		lookupKeys := viper.GetBool("img4.im4p.extract.lookup")
		lookupDevice := viper.GetString("img4.im4p.extract.lookup-device")
		lookupBuild := viper.GetString("img4.im4p.extract.lookup-build")
		// validate flags
		if extractExtra && extractKbag {
			return fmt.Errorf("cannot specify both --extra and --kbag")
		}

		filePath := filepath.Clean(args[0])

		// Check if decryption is requested
		decrypt := len(ivkeyStr) != 0 || len(ivStr) != 0 || len(keyStr) != 0 || lookupKeys
		if lookupKeys {
			if len(ivkeyStr) != 0 || len(ivStr) != 0 || len(keyStr) != 0 {
				return fmt.Errorf("cannot use --lookup with manual --iv-key, --iv, or --key flags")
			}

			// If device/build not provided, try to extract from folder structure
			if lookupDevice == "" || lookupBuild == "" {
				// Get absolute path of the file's directory
				absPath, err := filepath.Abs(filePath)
				if err != nil {
					return fmt.Errorf("failed to get absolute path: %v", err)
				}

				// Walk up the directory tree looking for the pattern
				dir := filepath.Dir(absPath)
				folderPattern := regexp.MustCompile(`^(?P<build>[A-Za-z0-9]+)__(?P<device>(AppleTV|AudioAccessory|iBridge|iP(hone|ad|od)|Mac(Book(Air|Pro)?|mini)?|RealityDevice|StudioDisplay|Watch)[0-9]+,[0-9]+)$`)

				for dir != "/" && dir != "." {
					baseName := filepath.Base(dir)
					if matches := folderPattern.FindStringSubmatch(baseName); matches != nil {
						detectedBuild := matches[1]
						detectedDevice := matches[2]

						log.Infof("Detected firmware folder: %s", baseName)
						utils.Indent(log.WithFields(log.Fields{
							"build":  detectedBuild,
							"device": detectedDevice,
						}).Info, 2)("Parsed firmware information")

						if lookupDevice == "" && lookupBuild == "" {
							useDetected := false
							prompt := &survey.Confirm{
								Message: fmt.Sprintf("Use detected build '%s' and device '%s' for key --lookup?", detectedBuild, detectedDevice),
								Default: true,
							}
							if err := survey.AskOne(prompt, &useDetected); err == terminal.InterruptErr {
								log.Warn("Exiting...")
								return nil
							}
							if useDetected {
								lookupDevice = detectedDevice
								lookupBuild = detectedBuild
							}
						}
						break
					}
					// Move up one directory
					dir = filepath.Dir(dir)
				}
			}
			if lookupDevice == "" || lookupBuild == "" {
				return fmt.Errorf("--lookup requires both --lookup-device and --lookup-build")
			}
			if extractExtra {
				return fmt.Errorf("cannot use --extra with decryption")
			}
		} else if decrypt {
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
			if rawExtract {
				outputPath = filepath.Join(filepath.Dir(filePath), baseName+".raw")
			} else if extractExtra {
				outputPath = filepath.Join(filepath.Dir(filePath), baseName+".extra")
			} else if decrypt {
				outputPath = filepath.Join(filepath.Dir(filePath), baseName+".dec")
			} else {
				outputPath = filepath.Join(filepath.Dir(filePath), baseName+".payload")
			}
		}

		im4p, err := img4.OpenPayload(filePath)
		if err != nil {
			return fmt.Errorf("failed to parse IM4P: %v", err)
		}

		if rawExtract {
			log.WithFields(log.Fields{
				"bytes": len(im4p.Data),
				"path":  outputPath,
			}).Info("Extracting Raw Data")

			return os.WriteFile(outputPath, im4p.Data, 0644)
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
				log.WithFields(log.Fields{
					"path": outputPath,
				}).Info("Writing keybags JSON to file")
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

			if lookupKeys {
				// Lookup keys from theapplewiki.com
				log.Info("Looking up decryption keys...")
				wikiKeys, err := download.GetWikiFirmwareKeys(&download.WikiConfig{
					Keys:   true,
					Device: lookupDevice,
					Build:  strings.ToUpper(lookupBuild),
				}, "", false)
				if err != nil {
					return fmt.Errorf("failed to lookup keys from theapplewiki.com: %v", err)
				}

				// Try to find key by exact filename match
				ivkeyStr, err = wikiKeys.GetKeyByFilename(filepath.Base(filePath))
				if err != nil {
					// If exact match fails, try to match by IM4P type
					if im4p.Type != "" {
						// Try patterns based on IM4P type
						patterns := []string{
							fmt.Sprintf("(?i)%s", im4p.Type),            // Match type case-insensitive
							fmt.Sprintf("(?i).*%s.*\\.im4p", im4p.Type), // Match type in filename
						}

						for _, pattern := range patterns {
							if ivkeyStr, err = wikiKeys.GetKeyByRegex(pattern); err == nil {
								break
							}
						}

						if err != nil {
							return fmt.Errorf("no key found for file '%s' (type: %s)", filepath.Base(filePath), im4p.Type)
						}
					} else {
						return fmt.Errorf("no key found for file '%s'", filepath.Base(filePath))
					}
				}

				// Decode the looked up key
				ivkey, err := hex.DecodeString(ivkeyStr)
				if err != nil {
					return fmt.Errorf("failed to decode looked up key: %v", err)
				}
				// ivkey must contain IV (aes.BlockSize bytes) and key
				if len(ivkey) < aes.BlockSize {
					return fmt.Errorf("looked up key too short for IV: need at least %d bytes, got %d", aes.BlockSize, len(ivkey))
				}
				iv = ivkey[:aes.BlockSize]
				key = ivkey[aes.BlockSize:]

				utils.Indent(log.WithFields(log.Fields{
					"iv":  fmt.Sprintf("%x", iv),
					"key": fmt.Sprintf("%x", key),
				}).Info, 2)("Found decryption keys")
			} else if len(ivkeyStr) != 0 {
				ivkey, err := hex.DecodeString(ivkeyStr)
				if err != nil {
					return fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				// ivkey must contain IV (aes.BlockSize bytes) and key
				if len(ivkey) < aes.BlockSize {
					return fmt.Errorf("--iv-key too short for IV: need at least %d bytes, got %d", aes.BlockSize, len(ivkey))
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

			log.WithFields(log.Fields{
				"path": outputPath,
			}).Info("Decrypting Payload")

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

			log.WithFields(log.Fields{
				"bytes": len(extraData),
				"path":  outputPath,
			}).Info("Extracting Extra Data")

			return os.WriteFile(outputPath, extraData, 0644)
		}

		if im4p.Encrypted {
			utils.Indent(log.Warn, 2)("extracting encrypted IM4P payload")
		}

		payloadData, err := im4p.GetData()
		if err != nil {
			return fmt.Errorf("failed to get payload data: %v", err)
		}

		if len(payloadData) == 0 {
			return fmt.Errorf("payload data is empty")
		}

		log.WithFields(log.Fields{
			"path": outputPath,
		}).Info("Extracting Payload")

		return os.WriteFile(outputPath, payloadData, 0644)
	},
}

// img4Im4pCreateCmd represents the im4p create command
var img4Im4pCreateCmd = &cobra.Command{
	Use:     "create <input-file>",
	Aliases: []string{"c"},
	Short:   "Create IM4P payload from raw data",
	Example: heredoc.Doc(`
		# Create IM4P from kernel with LZSS compression
		❯ ipsw img4 im4p create --type krnl --compress lzss kernelcache.bin

		# Create IM4P with version and extra data
		❯ ipsw img4 im4p create --type rkrn --version "RestoreKernel" --compress lzss --extra extra.bin kernel.bin

		# Create uncompressed IM4P
		❯ ipsw img4 im4p create --type logo --compress none logo.png

		# Create with custom output path
		❯ ipsw img4 im4p create --type dtre --output devicetree.im4p devicetree.bin`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		inputPath := filepath.Clean(args[0])

		if outputPath == "" {
			outputPath = filepath.Clean(inputPath) + ".im4p"
		}
		if !slices.Contains(img4.CompressionTypes, compressionType) {
			return fmt.Errorf("unsupported compression type: %s (supported: %s)", compressionType, strings.Join(img4.CompressionTypes, ", "))
		}

		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		var extraData []byte
		if len(extraPath) > 0 {
			if strings.ToLower(compressionType) == "lzfse" {
				log.Warn("'lzfse' compressed --extra data does NOT seem to be bootable by iBoot ('lzfse_iboot' compression is recommended for bootable images)")
				utils.Indent(log.Warn, 2)("NOTE: 'lzfse_iboot' currently only available on macOS")
			}
			if strings.ToLower(compressionType) == "none" || compressionType == "" {
				return fmt.Errorf("--extra requires compression (--compress 'lzss', 'lzfse', or 'lzfse_iboot') to detect --extra data boundaries during extraction")
			}
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
			Compression: compressionType,
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

		if err := os.WriteFile(outputPath, im4pData, 0644); err != nil {
			return fmt.Errorf("failed to write IM4P file: %v", err)
		}

		log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(im4pData))),
		}).Info("Created IM4P")

		return nil
	},
}
