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
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4CreateCmd)
	// Create from raw input file as payload data
	img4CreateCmd.Flags().StringP("input", "i", "", "Input file for IM4P payload data (raw data, not IM4P file)")
	img4CreateCmd.Flags().StringP("type", "t", "", "IM4P type to set")
	img4CreateCmd.Flags().StringP("version", "v", "", "IM4P version to set")
	img4CreateCmd.Flags().StringP("compress", "c", "none", fmt.Sprintf("IM4P compression to use (%s)", strings.Join(img4.CompressionTypes, ", ")))
	img4CreateCmd.RegisterFlagCompletionFunc("compress", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return img4.CompressionTypes, cobra.ShellCompDirectiveDefault
	})
	// Common flags
	img4CreateCmd.Flags().StringP("im4p", "p", "", "Input Img4 payload file")
	img4CreateCmd.Flags().StringP("im4m", "m", "", "Input Img4 manifest file")
	img4CreateCmd.Flags().StringP("im4r", "r", "", "Input Img4 restore info file")
	img4CreateCmd.Flags().StringP("boot-nonce", "g", "", "Boot nonce to set in Img4 restore info")
	img4CreateCmd.Flags().StringP("extra", "e", "", "Extra IM4P payload data to set")
	img4CreateCmd.Flags().StringP("output", "o", "", "Output file")
	// Mark required flags
	img4CreateCmd.MarkFlagRequired("output")
	// Mark file flags
	img4CreateCmd.MarkFlagFilename("input")
	img4CreateCmd.MarkFlagFilename("im4p")
	img4CreateCmd.MarkFlagFilename("im4m")
	img4CreateCmd.MarkFlagFilename("im4r")
	img4CreateCmd.MarkFlagFilename("extra")
	img4CreateCmd.MarkFlagFilename("output")
	// Mark mutually exclusive
	img4CreateCmd.MarkFlagsMutuallyExclusive("im4p", "input")
	img4CreateCmd.MarkFlagsMutuallyExclusive("im4r", "boot-nonce")
	// viper flags
	viper.BindPFlag("img4.create.input", img4CreateCmd.Flags().Lookup("input"))
	viper.BindPFlag("img4.create.type", img4CreateCmd.Flags().Lookup("type"))
	viper.BindPFlag("img4.create.version", img4CreateCmd.Flags().Lookup("version"))
	viper.BindPFlag("img4.create.compress", img4CreateCmd.Flags().Lookup("compress"))
	viper.BindPFlag("img4.create.im4p", img4CreateCmd.Flags().Lookup("im4p"))
	viper.BindPFlag("img4.create.im4m", img4CreateCmd.Flags().Lookup("im4m"))
	viper.BindPFlag("img4.create.im4r", img4CreateCmd.Flags().Lookup("im4r"))
	viper.BindPFlag("img4.create.boot-nonce", img4CreateCmd.Flags().Lookup("boot-nonce"))
	viper.BindPFlag("img4.create.extra", img4CreateCmd.Flags().Lookup("extra"))
	viper.BindPFlag("img4.create.output", img4CreateCmd.Flags().Lookup("output"))
}

// img4CreateCmd represents the create command
var img4CreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"c"},
	Short:   "Create an IMG4 file",
	Example: heredoc.Doc(`
		# Create IMG4 from existing IM4P with manifest and restore info
		❯ ipsw img4 create --im4p payload.im4p --im4m manifest.im4m --im4r restore.im4r --output kernel.img4

		# Create IMG4 from raw kernel with LZSS compression and manifest
		❯ ipsw img4 create --input kernelcache --type krnl --description "Kernelcache" --compress lzss --im4m manifest.im4m --output kernel.img4

		# Create IMG4 with boot nonce (generates IM4R automatically)
		❯ ipsw img4 create --input sep-firmware.bin --type sepi --boot-nonce 1234567890abcdef --im4m manifest.im4m --output sep.img4

		# Create IMG4 with extra data (extra data requires --compress lzss)
		❯ ipsw img4 create --input payload.bin --type logo --compress lzss --extra extra.bin --im4m manifest.im4m --output logo.img4

		# Create unsigned IMG4 (no manifest) - for testing only
		❯ ipsw img4 create --input test.bin --type test --description "Test payload" --output test.img4

		# Create IMG4 from iBoot with specific compression
		❯ ipsw img4 create --input iboot.raw --type ibot --description "iBoot" --compress lzfse --im4m iboot.im4m --output iboot.img4

		# Create IMG4 from raw data with common FourCC codes
		❯ ipsw img4 create --input kernelcache.bin --type krnl --compress lzss --im4m manifest.im4m --output kernel.img4
		❯ ipsw img4 create --input devicetree.bin --type dtre --compress lzss --im4m manifest.im4m --output devicetree.img4
		❯ ipsw img4 create --input ramdisk.dmg --type rdsk --compress lzss --im4m manifest.im4m --output ramdisk.img4

		# Re-type existing IM4P file with new type
		❯ ipsw img4 create --im4p existing.im4p --type newt --im4m manifest.im4m --output retyped.img4`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// flags
		inputPath := viper.GetString("img4.create.input")
		im4pType := viper.GetString("img4.create.type")
		im4pVersion := viper.GetString("img4.create.version")
		im4pCompression := viper.GetString("img4.create.compress")
		im4pExtraDataPath := viper.GetString("img4.create.extra")
		im4pPath := viper.GetString("img4.create.im4p")
		im4mPath := viper.GetString("img4.create.im4m")
		im4rPath := viper.GetString("img4.create.im4r")
		bootNonce := viper.GetString("img4.create.boot-nonce")
		outputPath := viper.GetString("img4.create.output")
		// validate flags
		if im4pPath == "" && inputPath == "" {
			return fmt.Errorf("must specify either --im4p or --input")
		}
		if inputPath != "" && im4pType == "" {
			return fmt.Errorf("--type is required when using --input")
		}
		if im4pType != "" && len(im4pType) != 4 {
			return fmt.Errorf("--type must be exactly 4 characters, got %d", len(im4pType))
		}
		if bootNonce != "" {
			if !regexp.MustCompile("^[0-9a-fA-F]{16}$").MatchString(bootNonce) {
				return fmt.Errorf("--boot-nonce must be exactly 16 hex characters")
			}
		}

		conf := &img4.CreateConfig{
			PayloadType:        im4pType,
			PayloadVersion:     im4pVersion,
			PayloadCompression: im4pCompression,
			BootNonce:          bootNonce,
		}

		if inputPath != "" {
			data, err := os.ReadFile(inputPath)
			if err != nil {
				return fmt.Errorf("failed to read input file: %v", err)
			}
			conf.InputData = data
		} else if im4pPath != "" {
			data, err := os.ReadFile(im4pPath)
			if err != nil {
				return fmt.Errorf("failed to read im4p file: %v", err)
			}
			conf.PayloadData = data
		}

		if im4pExtraDataPath != "" {
			if strings.ToLower(im4pCompression) != "lzss" {
				log.Warn("booting IMG4s with --extra data seems to work best with 'lzss' compression")
			}
			if strings.ToLower(im4pCompression) == "none" || im4pCompression == "" {
				return fmt.Errorf("--extra requires compression (--compress 'lzss' or 'lzfse_iboot') to detect --extra data boundaries during extraction")
			}
			data, err := os.ReadFile(im4pExtraDataPath)
			if err != nil {
				return fmt.Errorf("failed to read extra data file: %v", err)
			}
			conf.PayloadExtraData = data
		}

		if im4mPath != "" {
			data, err := os.ReadFile(im4mPath)
			if err != nil {
				return fmt.Errorf("failed to read im4m file: %v", err)
			}
			conf.ManifestData = data
		}

		if im4rPath != "" {
			data, err := os.ReadFile(im4rPath)
			if err != nil {
				return fmt.Errorf("failed to read im4r file: %v", err)
			}
			conf.RestoreInfoData = data
		}

		img, err := img4.Create(conf)
		if err != nil {
			return fmt.Errorf("failed to create IMG4: %v", err)
		}

		img4Data, err := img.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal IMG4: %v", err)
		}

		if err := os.WriteFile(outputPath, img4Data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %v", err)
		}

		log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(img4Data))),
		}).Info("Created IMG4")

		return nil
	},
}
