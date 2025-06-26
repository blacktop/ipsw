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
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/adler32"
	"math"
	"os"
	"regexp"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/lzfse-cgo"
	"github.com/blacktop/lzss"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	// ComplzssHeaderSize is the size of the complzss header
	ComplzssHeaderSize = 384
	// BootNonceLength is the required length of boot nonce in bytes
	BootNonceLength = 8
)

func init() {
	Img4Cmd.AddCommand(img4CreateCmd)
	// Create from existing IM4P
	img4CreateCmd.Flags().StringP("im4p", "p", "", "Input Image4 payload file")
	// Create from raw input file
	img4CreateCmd.Flags().StringP("input", "i", "", "Input file")
	img4CreateCmd.Flags().StringP("fourcc", "f", "", "FourCC to set")
	img4CreateCmd.Flags().StringP("description", "d", "", "Description to set")
	img4CreateCmd.Flags().Bool("lzss", false, "LZSS compress the data")
	img4CreateCmd.Flags().Bool("lzfse", false, "LZFSE compress the data")
	// Common flags
	img4CreateCmd.Flags().StringP("im4m", "m", "", "Input Image4 manifest file")
	img4CreateCmd.Flags().StringP("im4r", "r", "", "Input Image4 restore info file")
	img4CreateCmd.Flags().StringP("boot-nonce", "g", "", "Boot nonce to set in Image4 restore info")
	img4CreateCmd.Flags().StringP("extra", "e", "", "Extra IM4P payload data to set (requires --lzss)")
	img4CreateCmd.Flags().StringP("output", "o", "", "Output file")
	// Mark required flags
	img4CreateCmd.MarkFlagRequired("output")
	// Mark file flags
	img4CreateCmd.MarkFlagFilename("im4p")
	img4CreateCmd.MarkFlagFilename("input")
	img4CreateCmd.MarkFlagFilename("im4m")
	img4CreateCmd.MarkFlagFilename("im4r")
	img4CreateCmd.MarkFlagFilename("extra")
	img4CreateCmd.MarkFlagFilename("output")
	// Mark mutually exclusive
	img4CreateCmd.MarkFlagsMutuallyExclusive("lzss", "lzfse")
	img4CreateCmd.MarkFlagsMutuallyExclusive("im4p", "input")
	// viper flags
	viper.BindPFlag("img4.create.im4p", img4CreateCmd.Flags().Lookup("im4p"))
	viper.BindPFlag("img4.create.input", img4CreateCmd.Flags().Lookup("input"))
	viper.BindPFlag("img4.create.fourcc", img4CreateCmd.Flags().Lookup("fourcc"))
	viper.BindPFlag("img4.create.description", img4CreateCmd.Flags().Lookup("description"))
	viper.BindPFlag("img4.create.lzss", img4CreateCmd.Flags().Lookup("lzss"))
	viper.BindPFlag("img4.create.lzfse", img4CreateCmd.Flags().Lookup("lzfse"))
	viper.BindPFlag("img4.create.im4m", img4CreateCmd.Flags().Lookup("im4m"))
	viper.BindPFlag("img4.create.im4r", img4CreateCmd.Flags().Lookup("im4r"))
	viper.BindPFlag("img4.create.boot-nonce", img4CreateCmd.Flags().Lookup("boot-nonce"))
	viper.BindPFlag("img4.create.extra", img4CreateCmd.Flags().Lookup("extra"))
	viper.BindPFlag("img4.create.output", img4CreateCmd.Flags().Lookup("output"))
}

// img4CreateCmd represents the create command
var img4CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an IMG4 file",
	Example: heredoc.Doc(`
		# Create IMG4 from existing IM4P with manifest and restore info
		❯ ipsw img4 create --im4p payload.im4p --im4m manifest.im4m --im4r restore.im4r --output kernel.img4

		# Create IMG4 from raw kernel with LZSS compression and manifest
		❯ ipsw img4 create --input kernelcache --fourcc krnl --description "Kernelcache" --lzss --im4m manifest.im4m --output kernel.img4

		# Create IMG4 with boot nonce (generates IM4R automatically)
		❯ ipsw img4 create --input sep-firmware.bin --fourcc sepi --boot-nonce 1234567890abcdef --im4m manifest.im4m --output sep.img4

		# Create IMG4 with extra data (extra data requires --lzss compression)
		❯ ipsw img4 create --input payload.bin --fourcc logo --lzss --extra extra.bin --im4m manifest.im4m --output logo.img4

		# Create unsigned IMG4 (no manifest) - for testing only
		❯ ipsw img4 create --input test.bin --fourcc test --description "Test payload" --output test.img4

		# Create IMG4 from iBoot with specific compression
		❯ ipsw img4 create --input iboot.raw --fourcc ibot --description "iBoot" --lzfse --im4m iboot.im4m --output iboot.img4

		# Create IMG4 from raw data with common FourCC codes
		❯ ipsw img4 create --input kernelcache.bin --fourcc krnl --lzss --im4m manifest.im4m --output kernel.img4
		❯ ipsw img4 create --input devicetree.bin --fourcc dtre --lzss --im4m manifest.im4m --output devicetree.img4
		❯ ipsw img4 create --input ramdisk.dmg --fourcc rdsk --lzss --im4m manifest.im4m --output ramdisk.img4`),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		im4pPath := viper.GetString("img4.create.im4p")
		inputPath := viper.GetString("img4.create.input")
		fourcc := viper.GetString("img4.create.fourcc")
		description := viper.GetString("img4.create.description")
		useLzss := viper.GetBool("img4.create.lzss")
		useLzfse := viper.GetBool("img4.create.lzfse")
		manifestPath := viper.GetString("img4.create.im4m")
		restoreInfoPath := viper.GetString("img4.create.im4r")
		bootNonce := viper.GetString("img4.create.boot-nonce")
		extraPath := viper.GetString("img4.create.extra")
		outputPath := viper.GetString("img4.create.output")
		// validate flags
		if im4pPath == "" && inputPath == "" {
			return fmt.Errorf("must specify either --im4p or --input")
		}
		if inputPath != "" && fourcc == "" {
			return fmt.Errorf("--fourcc is required when using --input")
		}
		// Validate FourCC format
		if fourcc != "" && len(fourcc) != 4 {
			return fmt.Errorf("fourcc must be exactly 4 characters, got %d", len(fourcc))
		}
		if extraPath != "" && !useLzss {
			return fmt.Errorf("extra data requires LZSS compression (--lzss)")
		}
		if bootNonce != "" && restoreInfoPath != "" {
			return fmt.Errorf("--boot-nonce and --im4r are mutually exclusive (boot-nonce generates IM4R)")
		}

		if im4pPath != "" {
			// When using existing IM4P, extra data should be passed to createImg4FromIm4p
			return createImg4FromIm4p(im4pPath, manifestPath, restoreInfoPath, outputPath, extraPath, bootNonce)
		}

		compressionType := "none"
		if useLzss {
			compressionType = "lzss"
		} else if useLzfse {
			compressionType = "lzfse"
		}
		return createImg4FromRaw(inputPath, fourcc, description, compressionType, manifestPath, restoreInfoPath, outputPath, extraPath, bootNonce)
	},
}

func createImg4FromRaw(inputPath, fourcc, description, compressionType, manifestPath, restoreInfoPath, outputPath, extraPath, bootNonce string) error {
	tmp, err := os.CreateTemp("", "img4_create_*.im4p")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmp.Name()); err != nil {
			log.WithError(err).Warnf("Failed to remove temporary file: %s", tmp.Name())
		}
	}()

	if err := createIm4pFromRaw(inputPath, tmp.Name(), fourcc, description, compressionType, extraPath); err != nil {
		return fmt.Errorf("failed to create IM4P: %v", err)
	}

	// Extra data already included in IM4P, don't pass it again
	return createImg4FromIm4p(tmp.Name(), manifestPath, restoreInfoPath, outputPath, "", bootNonce)
}

func createImg4FromIm4p(payloadPath, manifestPath, restoreInfoPath, outputPath, extraPath, bootNonce string) error {
	payloadData, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read payload file: %v", err)
	}

	var extraData []byte
	if extraPath != "" {
		extraData, err = os.ReadFile(extraPath)
		if err != nil {
			return fmt.Errorf("failed to read extra data file: %v", err)
		}
		payloadData = append(payloadData, extraData...)
	}

	var manifestData []byte
	if manifestPath != "" {
		manifestData, err = os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest file: %v", err)
		}
	}

	var restoreInfoData []byte
	if restoreInfoPath != "" {
		restoreInfoData, err = os.ReadFile(restoreInfoPath)
		if err != nil {
			return fmt.Errorf("failed to read restore info file: %v", err)
		}
	} else if bootNonce != "" {
		// Validate boot nonce format
		if !regexp.MustCompile("^[0-9a-fA-F]{16}$").MatchString(bootNonce) {
			return fmt.Errorf("boot nonce must be exactly 16 hex characters")
		}
		nonce, err := hex.DecodeString(bootNonce)
		if err != nil {
			return fmt.Errorf("failed to decode boot nonce: %v", err)
		}
		if len(nonce) != BootNonceLength {
			return fmt.Errorf("boot nonce must be exactly %d bytes (%d hex characters), got %d bytes", BootNonceLength, BootNonceLength*2, len(nonce))
		}
		restoreInfoData = createIm4r(nonce)
	}

	img4Data, err := img4.CreateImg4File(payloadData, manifestData, restoreInfoData)
	if err != nil {
		return fmt.Errorf("failed to create IMG4: %v", err)
	}

	if err := os.WriteFile(outputPath, img4Data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	utils.Indent(log.WithFields(log.Fields{
		"path": outputPath,
		"size": humanize.Bytes(uint64(len(img4Data))),
	}).Info, 2)("Created IMG4")

	return nil
}

// createIm4r creates an IM4R (Image4 Restore Info) structure with the given boot nonce.
// This creates a simplified IM4R that matches the format expected by reference implementations.
func createIm4r(nonce []byte) []byte {
	// Create a simplified IM4R structure that contains the boot nonce directly
	// This matches the format expected by both the C and Rust reference implementations

	// Create the generator data containing BNCN + boot nonce
	generatorData := make([]byte, 0, 4+len(nonce))
	generatorData = append(generatorData, []byte("BNCN")...)
	generatorData = append(generatorData, nonce...)

	im4rStruct := struct {
		Name      string `asn1:"ia5"`
		Generator []byte
	}{
		Name:      "IM4R",
		Generator: generatorData,
	}

	im4rData, err := asn1.Marshal(im4rStruct)
	if err != nil {
		// Fallback to simple format if marshaling fails
		return append([]byte("IM4RBNCN"), nonce...)
	}

	return im4rData
}

func createIm4pFromRaw(inputPath, outputPath, fourcc, description, compressionType, extraPath string) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	var extraData []byte
	if extraPath != "" {
		extraData, err = os.ReadFile(extraPath)
		if err != nil {
			return fmt.Errorf("failed to read extra data file: %v", err)
		}
	}

	originalSize := len(inputData)
	payloadData := inputData
	compressionType = strings.ToLower(strings.TrimSpace(compressionType))

	switch compressionType {
	case "lzss":
		utils.Indent(log.Debug, 2)("Compressing payload with LZSS...")
		compressedData := lzss.Compress(inputData)
		if len(compressedData) > 0 && len(compressedData) < len(inputData) {
			// Create complzss header + compressed data
			payloadData, err = createComplzssData(inputData, compressedData)
			if err != nil {
				return fmt.Errorf("failed to create complzss data: %v", err)
			}
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Compression: %d → %d bytes (%.1f%% reduction)",
				originalSize, len(payloadData),
				float64(originalSize-len(payloadData))/float64(originalSize)*100))
		} else {
			utils.Indent(log.Debug, 2)("LZSS compression ineffective, using original data")
		}
	case "lzfse":
		utils.Indent(log.Debug, 2)("Compressing payload with LZFSE...")
		compressedData := lzfse.EncodeBuffer(inputData)
		if len(compressedData) > 0 && len(compressedData) < len(inputData) {
			payloadData = compressedData
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Compression: %d → %d bytes (%.1f%% reduction)",
				originalSize, len(compressedData),
				float64(originalSize-len(compressedData))/float64(originalSize)*100))
		} else {
			utils.Indent(log.Debug, 2)("LZFSE compression ineffective, using original data")
		}
	case "none", "":
		utils.Indent(log.Debug, 2)("No compression requested")
	default:
		return fmt.Errorf("unsupported compression type: %s (supported: lzfse, lzss, none)", compressionType)
	}

	asn1Data, err := img4.CreateIm4pFileWithExtra(fourcc, description, payloadData, extraData)
	if err != nil {
		return fmt.Errorf("failed to encode IM4P: %v", err)
	}

	if err := os.WriteFile(outputPath, asn1Data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	utils.Indent(log.WithFields(log.Fields{
		"path": outputPath,
		"size": humanize.Bytes(uint64(len(asn1Data))),
	}).Debug, 2)("Created IM4P")

	return nil
}

type lzssHeader struct {
	Magic           [8]byte
	Adler32         uint32
	UncompressedLen uint32
	CompressedLen   uint32
	Version         uint32
	Padding         [360]byte
}

// createComplzssData creates a complete LZSS compressed data structure with complzss header
func createComplzssData(uncompressedData, compressedData []byte) ([]byte, error) {
	if len(compressedData) > math.MaxInt-ComplzssHeaderSize {
		return nil, fmt.Errorf("compressed data too large: %d bytes (max %d bytes)", len(compressedData), math.MaxInt-ComplzssHeaderSize)
	}

	header := lzssHeader{
		Adler32:         adler32.Checksum(uncompressedData),
		UncompressedLen: uint32(len(uncompressedData)),
		CompressedLen:   uint32(len(compressedData)),
		Version:         1,
	}
	copy(header.Magic[:], "complzss")

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, header); err != nil {
		return nil, fmt.Errorf("failed to write complzss header: %v", err)
	}
	if _, err := buf.Write(compressedData); err != nil {
		return nil, fmt.Errorf("failed to write compressed data: %v", err)
	}

	return buf.Bytes(), nil
}
