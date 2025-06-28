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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4Im4mCmd)

	// Add subcommands to im4m
	img4Im4mCmd.AddCommand(img4Im4mInfoCmd)
	img4Im4mCmd.AddCommand(img4Im4mExtractCmd)
	img4Im4mCmd.AddCommand(img4Im4mVerifyCmd)
	img4Im4mCmd.AddCommand(img4Im4mPersonalizeCmd)

	// Info command flags
	img4Im4mInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4mInfoCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4m.info.json", img4Im4mInfoCmd.Flags().Lookup("json"))

	// Extract command flags
	img4Im4mExtractCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4mExtractCmd.Flags().BoolP("update", "u", false, "Extract update Image4 manifest (if available)")
	img4Im4mExtractCmd.Flags().BoolP("no-nonce", "n", false, "Extract no-nonce Image4 manifest (if available)")
	img4Im4mExtractCmd.MarkFlagFilename("output")
	img4Im4mExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4m.extract.output", img4Im4mExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4m.extract.update", img4Im4mExtractCmd.Flags().Lookup("update"))
	viper.BindPFlag("img4.im4m.extract.no-nonce", img4Im4mExtractCmd.Flags().Lookup("no-nonce"))

	// Verify command flags
	img4Im4mVerifyCmd.Flags().StringP("build-manifest", "b", "", "Build manifest file for verification")
	img4Im4mVerifyCmd.Flags().Bool("allow-extra", false, "Allow IM4M to have properties not in build manifest")
	img4Im4mVerifyCmd.MarkFlagRequired("build-manifest")
	img4Im4mVerifyCmd.MarkFlagFilename("build-manifest")
	viper.BindPFlag("img4.im4m.verify.build-manifest", img4Im4mVerifyCmd.Flags().Lookup("build-manifest"))
	viper.BindPFlag("img4.im4m.verify.allow-extra", img4Im4mVerifyCmd.Flags().Lookup("allow-extra"))

	// Personalize command flags
	img4Im4mPersonalizeCmd.Flags().StringP("output", "o", "", "Output personalized IMG4 file")
	img4Im4mPersonalizeCmd.Flags().String("ecid", "", "Device ECID for personalization")
	img4Im4mPersonalizeCmd.Flags().String("nonce", "", "Device nonce for personalization")
	img4Im4mPersonalizeCmd.MarkFlagRequired("output")
	img4Im4mPersonalizeCmd.MarkFlagFilename("output")
	viper.BindPFlag("img4.im4m.personalize.output", img4Im4mPersonalizeCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4m.personalize.ecid", img4Im4mPersonalizeCmd.Flags().Lookup("ecid"))
	viper.BindPFlag("img4.im4m.personalize.nonce", img4Im4mPersonalizeCmd.Flags().Lookup("nonce"))
}

// img4Im4mCmd represents the im4m command group
var img4Im4mCmd = &cobra.Command{
	Use:   "im4m",
	Short: "IM4M manifest operations",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4mInfoCmd represents the im4m info command
var img4Im4mInfoCmd = &cobra.Command{
	Use:           "info <IM4M>",
	Short:         "Display IM4M manifest information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		manifest, err := img4.OpenManifest(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed to parse IM4M: %v", err)
		}

		if viper.GetBool("img4.im4m.info.json") {
			jsonData, err := json.Marshal(manifest)
			if err != nil {
				return fmt.Errorf("failed to marshal IM4M to JSON: %v", err)
			}
			fmt.Println(string(jsonData))
		} else {
			fmt.Println(manifest)
		}

		return nil
	},
}

// img4Im4mExtractCmd represents the im4m extract command
var img4Im4mExtractCmd = &cobra.Command{
	Use:           "extract <IM4M>",
	Short:         "Extract IM4M manifest from SHSH blob",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		outputPath := viper.GetString("img4.im4m.extract.output")
		extractUpdate := viper.GetBool("img4.im4m.extract.update")
		extractNoNonce := viper.GetBool("img4.im4m.extract.no-nonce")

		if outputPath == "" {
			suffix := ".im4m"
			if extractUpdate {
				suffix = ".update.im4m"
			} else if extractNoNonce {
				suffix = ".no-nonce.im4m"
			}
			outputPath = filepath.Clean(filePath) + suffix
		}

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		manifestData, err := img4.ExtractManifestFromShshWithOptions(f, extractUpdate, extractNoNonce)
		if err != nil {
			return fmt.Errorf("failed to extract manifest from SHSH blob: %v", err)
		}

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(manifestData))),
		}).Info, 2)("Extracting IM4M")

		return os.WriteFile(outputPath, manifestData, 0644)
	},
}

// img4Im4mVerifyCmd represents the im4m verify command
var img4Im4mVerifyCmd = &cobra.Command{
	Use:           "verify <IM4M>",
	Short:         "Verify IM4M manifest against build manifest",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		buildManifestPath := viper.GetString("img4.im4m.verify.build-manifest")

		inputFile, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open input manifest %s: %v", args[0], err)
		}
		defer inputFile.Close()

		data, err := io.ReadAll(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input manifest %s: %v", args[0], err)
		}

		inputManifest, err := img4.ParseManifest(data)
		if err != nil {
			return fmt.Errorf("failed to parse input IM4M manifest: %v", err)
		}

		bmData, err := os.ReadFile(buildManifestPath)
		if err != nil {
			return fmt.Errorf("failed to read build manifest %s: %v", buildManifestPath, err)
		}
		buildManifest, err := plist.ParseBuildManifest(bmData)
		if err != nil {
			return fmt.Errorf("failed to parse build manifest: %v", err)
		}

		result, err := img4.VerifyManifestProperties(inputManifest, buildManifest, viper.GetBool("verbose"), viper.GetBool("img4.im4m.verify.allow-extra"))
		if err != nil {
			return fmt.Errorf("verification failed: %v", err)
		}

		if result.IsValid {
			fmt.Printf("\n%s ✓ Manifest verification %s\n",
				color.New(color.FgGreen).Sprint("SUCCESS:"),
				color.New(color.FgGreen).Sprint("PASSED"))
		} else {
			fmt.Printf("\n%s ✗ Manifest verification %s\n",
				color.New(color.FgRed).Sprint("FAILED:"),
				color.New(color.FgRed).Sprint("FAILED"))
			for _, mismatch := range result.Mismatches {
				fmt.Printf("  Property: %s, Expected: %v, Actual: %v\n", mismatch.Property, mismatch.Expected, mismatch.Actual)
			}
		}

		return nil
	},
}

// img4Im4mPersonalizeCmd represents the im4m personalize command
var img4Im4mPersonalizeCmd = &cobra.Command{
	Use:           "personalize",
	Short:         "🚧 Create personalized IM4M manifest with device-specific values",
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true, // Hidden until fully implemented
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// NOTE: this is experimental and the IMG4 will not be valid without a proper TSS response
		log.Warn("This is an experimental command and the created IMG4 will NOT be valid")

		outputPath := viper.GetString("img4.im4m.personalize.output")
		ecid := viper.GetString("img4.im4m.personalize.ecid")
		nonce := viper.GetString("img4.im4m.personalize.nonce")

		infile := filepath.Clean(args[0])

		inputImg, err := img4.Open(infile)
		if err != nil {
			return fmt.Errorf("failed to parse input IMG4: %v", err)
		}

		personalizedImg, err := personalizeImg4(inputImg, ecid, nonce, viper.GetBool("verbose"))
		if err != nil {
			return fmt.Errorf("personalization failed: %v", err)
		}

		img, err := img4.Create(&img4.CreateConfig{
			PayloadData:     personalizedImg.PayloadData,
			ManifestData:    personalizedImg.ManifestData,
			RestoreInfoData: personalizedImg.RestoreInfoData,
		})
		if err != nil {
			return fmt.Errorf("failed to create personalized IMG4: %v", err)
		}

		personalizedData, err := img.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal personalized IMG4: %v", err)
		}

		if err := os.WriteFile(outputPath, personalizedData, 0644); err != nil {
			return fmt.Errorf("failed to write personalized IMG4: %v", err)
		}

		utils.Indent(log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(personalizedData))),
		}).Info, 2)("Personalization")

		return nil
	},
}

// PersonalizedImg4 holds the components of a personalized IMG4
type PersonalizedImg4 struct {
	PayloadData     []byte
	ManifestData    []byte
	RestoreInfoData []byte
}

func personalizeImg4(img *img4.Image, ecid, nonce string, verbose bool) (*PersonalizedImg4, error) {
	if verbose {
		log.Debug("Starting personalization process")
		if ecid != "" {
			log.Debugf("Using ECID: %s", ecid)
		}
		if nonce != "" {
			log.Debugf("Using nonce: %s", nonce)
		}
	}

	// Validate required parameters
	if ecid == "" {
		return nil, fmt.Errorf("ECID is required for personalization")
	}
	if nonce == "" {
		return nil, fmt.Errorf("nonce is required for personalization")
	}

	// Parse ECID
	ecidValue, err := strconv.ParseUint(ecid, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid ECID format: %w", err)
	}

	// Parse nonce (expected as hex string)
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(nonce, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid nonce format (expected hex): %w", err)
	}

	if verbose {
		log.Debugf("Parsed ECID: 0x%x", ecidValue)
		log.Debugf("Parsed nonce: %x", nonceBytes)
	}

	// Extract payload data from IMG4
	// Check if the input contains IM4P data that we can extract
	var payloadData []byte

	// For a complete IMG4 personalization, we would need the IM4P data
	// This is a limitation of the current implementation - production TSS
	// personalization works with the complete IPSW bundle containing IM4P files
	if verbose {
		log.Debug("Note: Personalization requires IM4P payload data")
		log.Debug("In production, this would extract from the IPSW/OTA bundle")
	}

	// Create a personalized manifest by modifying the existing manifest properties
	personalizedProperties := make(map[string]any)

	if img.Manifest.Properties != nil {
		// Copy existing properties
		existingProps := img4.ConvertPropertySliceToMap(img.Manifest.Properties)
		maps.Copy(personalizedProperties, existingProps)
	}

	// Update with device-specific values
	personalizedProperties["ECID"] = ecidValue
	personalizedProperties["ApNonce"] = nonceBytes

	if verbose {
		log.Debug("Updating manifest with personalization values:")
		log.Debugf("  ECID: 0x%x", ecidValue)
		log.Debugf("  ApNonce: %x", nonceBytes)
	}

	// Create a new manifest with personalized properties
	personalizedManifest, err := createPersonalizedManifest(img.Manifest.Raw, personalizedProperties)
	if err != nil {
		return nil, fmt.Errorf("failed to create personalized manifest: %w", err)
	}

	result := &PersonalizedImg4{
		PayloadData:     payloadData,
		ManifestData:    personalizedManifest,
		RestoreInfoData: []byte{}, // Would be populated with TSS response in full implementation
	}

	if verbose {
		log.Debug("Personalization complete with device-specific values")
		log.Info("Note: For production use with Apple's TSS servers:")
		log.Info("  1. Use 'ipsw tss' command for official TSS blob requests")
		log.Info("  2. Use 'ipsw ssh shsh' for extracting SHSH blobs from devices")
		log.Info("  3. Use 'ipsw device' to get additional device parameters")
	}

	return result, nil
}

func createPersonalizedManifest(originalManifestData []byte, personalizedProperties map[string]any) ([]byte, error) {
	// Create a personalized IM4M manifest with the device-specific ECID and nonce
	// This creates a new manifest structure with the personalized values

	// Create manifest properties structure with personalized values
	var props []byte
	var err error

	// Encode the personalized properties as a simple structure
	// In production, this would be a full ASN.1 IM4M structure
	propBuffer := bytes.NewBuffer(nil)

	// Write ECID property (if provided)
	if ecid, exists := personalizedProperties["ECID"]; exists {
		if ecidVal, ok := ecid.(uint64); ok {
			// Create a simple property structure: [tag][length][value]
			ecidBytes := make([]byte, 8)
			for i := range 8 {
				ecidBytes[7-i] = byte(ecidVal >> (i * 8))
			}
			propBuffer.WriteString("ECID")
			propBuffer.Write([]byte{0x08}) // length
			propBuffer.Write(ecidBytes)
		}
	}

	// Write nonce property (if provided)
	if nonce, exists := personalizedProperties["ApNonce"]; exists {
		if nonceBytes, ok := nonce.([]byte); ok {
			propBuffer.WriteString("APNC")                  // ApNonce tag
			propBuffer.Write([]byte{byte(len(nonceBytes))}) // length
			propBuffer.Write(nonceBytes)
		}
	}

	props = propBuffer.Bytes()

	// Create a basic IM4M structure with personalized data
	// This is a simplified version - production would use proper ASN.1 encoding
	manifestBuffer := bytes.NewBuffer(nil)

	// IM4M header
	manifestBuffer.WriteString("IM4M") // Magic

	// Version (simplified)
	manifestBuffer.Write([]byte{0x00, 0x00, 0x00, 0x01}) // Version 1

	// Properties length
	propsLen := len(props)
	manifestBuffer.Write([]byte{
		byte(propsLen >> 24),
		byte(propsLen >> 16),
		byte(propsLen >> 8),
		byte(propsLen),
	})

	// Properties data
	manifestBuffer.Write(props)

	// Add original certificate data if available (simplified)
	if len(originalManifestData) > 16 {
		// Append some of the original signing data to maintain structure
		// In production, this would be properly reconstructed and re-signed
		manifestBuffer.Write(originalManifestData[16:])
	}

	return manifestBuffer.Bytes(), err
}
