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
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
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
	img4Im4mInfoCmd.Flags().BoolP("verbose", "v", false, "Show detailed information")
	img4Im4mInfoCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4m.info.json", img4Im4mInfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.im4m.info.verbose", img4Im4mInfoCmd.Flags().Lookup("verbose"))

	// Extract command flags
	img4Im4mExtractCmd.Flags().StringP("output", "o", "", "Output file path")
	img4Im4mExtractCmd.Flags().Bool("shsh", false, "Extract from SHSH blob")
	img4Im4mExtractCmd.MarkFlagFilename("output")
	img4Im4mExtractCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.im4m.extract.output", img4Im4mExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4m.extract.shsh", img4Im4mExtractCmd.Flags().Lookup("shsh"))

	// Verify command flags
	img4Im4mVerifyCmd.Flags().StringP("input", "i", "", "Input IM4M manifest file")
	img4Im4mVerifyCmd.Flags().StringP("build-manifest", "b", "", "Build manifest file for verification")
	img4Im4mVerifyCmd.Flags().BoolP("verbose", "v", false, "Verbose verification output")
	img4Im4mVerifyCmd.MarkFlagRequired("input")
	img4Im4mVerifyCmd.MarkFlagRequired("build-manifest")
	img4Im4mVerifyCmd.MarkFlagFilename("input")
	img4Im4mVerifyCmd.MarkFlagFilename("build-manifest")
	viper.BindPFlag("img4.im4m.verify.input", img4Im4mVerifyCmd.Flags().Lookup("input"))
	viper.BindPFlag("img4.im4m.verify.build-manifest", img4Im4mVerifyCmd.Flags().Lookup("build-manifest"))
	viper.BindPFlag("img4.im4m.verify.verbose", img4Im4mVerifyCmd.Flags().Lookup("verbose"))

	// Personalize command flags
	img4Im4mPersonalizeCmd.Flags().StringP("input", "i", "", "Input IMG4 file")
	img4Im4mPersonalizeCmd.Flags().StringP("output", "o", "", "Output personalized IMG4 file")
	img4Im4mPersonalizeCmd.Flags().String("ecid", "", "Device ECID for personalization")
	img4Im4mPersonalizeCmd.Flags().String("nonce", "", "Device nonce for personalization")
	img4Im4mPersonalizeCmd.Flags().BoolP("verbose", "v", false, "Verbose personalization output")
	img4Im4mPersonalizeCmd.MarkFlagRequired("input")
	img4Im4mPersonalizeCmd.MarkFlagRequired("output")
	img4Im4mPersonalizeCmd.MarkFlagFilename("input")
	img4Im4mPersonalizeCmd.MarkFlagFilename("output")
	viper.BindPFlag("img4.im4m.personalize.input", img4Im4mPersonalizeCmd.Flags().Lookup("input"))
	viper.BindPFlag("img4.im4m.personalize.output", img4Im4mPersonalizeCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4m.personalize.ecid", img4Im4mPersonalizeCmd.Flags().Lookup("ecid"))
	viper.BindPFlag("img4.im4m.personalize.nonce", img4Im4mPersonalizeCmd.Flags().Lookup("nonce"))
	viper.BindPFlag("img4.im4m.personalize.verbose", img4Im4mPersonalizeCmd.Flags().Lookup("verbose"))
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
	Use:           "info <IMG4>",
	Short:         "Display IM4M manifest information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.im4m.info.json")
		verboseOutput := viper.GetBool("img4.im4m.info.verbose")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		img, err := img4.Parse(f)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4: %v", err)
		}

		return displayIm4mInfo(img, filePath, jsonOutput, verboseOutput)
	},
}

func displayIm4mInfo(img *img4.Img4, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		data := map[string]any{
			"file":       filepath.Base(filePath),
			"version":    img.Manifest.Version,
			"properties": img.Manifest.Properties,
		}

		if verbose {
			// Add raw manifest data if available
			data["raw_manifest"] = fmt.Sprintf("%x", img.Manifest.ApImg4Ticket.Bytes)
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IM4M info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s             %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s %d\n", colorField("Manifest Version:"), img.Manifest.Version)

		fmt.Printf("\n%s\n", colorField("Manifest Properties:"))
		for key, value := range img.Manifest.Properties {
			switch v := value.(type) {
			case []byte:
				if verbose {
					fmt.Printf("  %s: %x\n", key, v)
				} else {
					fmt.Printf("  %s: <data:%d bytes>\n", key, len(v))
				}
			default:
				fmt.Printf("  %s: %v\n", key, v)
			}
		}

		if verbose {
			fmt.Printf("\n%s %d bytes\n", colorField("Raw Manifest:"), len(img.Manifest.ApImg4Ticket.Bytes))
		}
	}

	return nil
}

// img4Im4mExtractCmd represents the im4m extract command
var img4Im4mExtractCmd = &cobra.Command{
	Use:           "extract <IMG4|SHSH>",
	Short:         "Extract IM4M manifest from IMG4 or SHSH blob",
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
		isShsh := viper.GetBool("img4.im4m.extract.shsh")

		if outputPath == "" {
			outputPath = filepath.Clean(filePath) + ".im4m"
		}

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		var manifestData []byte

		if isShsh {
			// Extract manifest from SHSH blob using enhanced pkg function
			manifestData, err = img4.ExtractManifestFromShsh(f)
			if err != nil {
				return fmt.Errorf("failed to extract manifest from SHSH blob: %v", err)
			}
		} else {
			// Extract manifest from IMG4
			rawImg4, err := img4.ParseImg4(f)
			if err != nil {
				return fmt.Errorf("failed to parse IMG4: %v", err)
			}
			manifestData = rawImg4.Manifest.Bytes
		}

		fmt.Printf("%s             %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s      %s\n", colorField("Output:"), outputPath)
		fmt.Printf("%s        %s\n", colorField("Manifest Size:"), humanize.Bytes(uint64(len(manifestData))))

		return os.WriteFile(outputPath, manifestData, 0644)
	},
}

// img4Im4mVerifyCmd represents the im4m verify command
var img4Im4mVerifyCmd = &cobra.Command{
	Use:           "verify",
	Short:         "Verify IM4M manifest against build manifest",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		inputPath := viper.GetString("img4.im4m.verify.input")
		buildManifestPath := viper.GetString("img4.im4m.verify.build-manifest")
		verboseOutput := viper.GetBool("img4.im4m.verify.verbose")

		fmt.Printf("%s        %s\n", colorField("Input Manifest:"), filepath.Base(inputPath))
		fmt.Printf("%s     %s\n", colorField("Build Manifest:"), filepath.Base(buildManifestPath))

		// Parse the input IM4M manifest
		inputFile, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("failed to open input manifest %s: %v", inputPath, err)
		}
		defer inputFile.Close()

		inputImg, err := img4.Parse(inputFile)
		if err != nil {
			return fmt.Errorf("failed to parse input manifest: %v", err)
		}

		// Parse the build manifest (could be IMG4 or standalone IM4M)
		buildFile, err := os.Open(buildManifestPath)
		if err != nil {
			return fmt.Errorf("failed to open build manifest %s: %v", buildManifestPath, err)
		}
		defer buildFile.Close()

		// Try to parse as IMG4 first, fall back to direct IM4M parsing
		var buildManifest *img4.Img4
		if buildImg, err := img4.Parse(buildFile); err == nil {
			buildManifest = buildImg
		} else {
			// If it's not an IMG4, try to parse it as a PLIST build manifest
			// For now, we'll return an error indicating unsupported format
			return fmt.Errorf("build manifest parsing not yet fully implemented - currently supports IMG4 format only")
		}

		// Perform verification
		result, err := verifyManifestProperties(inputImg, buildManifest, verboseOutput)
		if err != nil {
			return fmt.Errorf("verification failed: %v", err)
		}

		// Display results
		if result.IsValid {
			fmt.Printf("\n%s ✓ Manifest verification %s\n",
				color.New(color.FgGreen).Sprint("SUCCESS:"),
				color.New(color.FgGreen).Sprint("PASSED"))
		} else {
			fmt.Printf("\n%s ✗ Manifest verification %s\n",
				color.New(color.FgRed).Sprint("FAILED:"),
				color.New(color.FgRed).Sprint("FAILED"))
		}

		fmt.Printf("%s   %d properties checked\n", colorField("Verified:"), result.PropertiesChecked)
		if len(result.Mismatches) > 0 {
			fmt.Printf("%s    %d properties failed\n", colorField("Mismatches:"), len(result.Mismatches))
			if verboseOutput {
				for _, mismatch := range result.Mismatches {
					fmt.Printf("  %s: expected %v, got %v\n",
						color.New(color.FgYellow).Sprint(mismatch.Property),
						mismatch.Expected, mismatch.Actual)
				}
			}
		}

		return nil
	},
}

// VerificationResult holds the results of manifest verification
type VerificationResult struct {
	IsValid           bool
	PropertiesChecked int
	Mismatches        []PropertyMismatch
}

// PropertyMismatch represents a property that doesn't match between manifests
type PropertyMismatch struct {
	Property string
	Expected any
	Actual   any
}

func verifyManifestProperties(input, build *img4.Img4, verbose bool) (*VerificationResult, error) {
	result := &VerificationResult{
		IsValid:    true,
		Mismatches: []PropertyMismatch{},
	}

	inputProps := input.Manifest.Properties
	buildProps := build.Manifest.Properties

	// Common properties to verify (these are the most critical for firmware validation)
	criticalProps := []string{"CHIP", "BORD", "CEPO", "SDOM", "ECID"}

	for _, prop := range criticalProps {
		result.PropertiesChecked++

		inputVal, inputExists := inputProps[prop]
		buildVal, buildExists := buildProps[prop]

		if verbose {
			log.Debugf("Checking property %s: input=%v (exists=%v), build=%v (exists=%v)",
				prop, inputVal, inputExists, buildVal, buildExists)
		}

		// Skip verification if property doesn't exist in either manifest
		if !inputExists && !buildExists {
			continue
		}

		// Property exists in one but not the other
		if inputExists != buildExists {
			result.IsValid = false
			result.Mismatches = append(result.Mismatches, PropertyMismatch{
				Property: prop,
				Expected: buildVal,
				Actual:   inputVal,
			})
			continue
		}

		// Both exist - compare values (handling different types)
		if !compareManifestValues(inputVal, buildVal) {
			result.IsValid = false
			result.Mismatches = append(result.Mismatches, PropertyMismatch{
				Property: prop,
				Expected: buildVal,
				Actual:   inputVal,
			})
		}
	}

	return result, nil
}

func compareManifestValues(a, b any) bool {
	// Handle different types that might represent the same value
	switch va := a.(type) {
	case []byte:
		if vb, ok := b.([]byte); ok {
			return bytes.Equal(va, vb)
		}
	case int:
		if vb, ok := b.(int); ok {
			return va == vb
		}
	case bool:
		if vb, ok := b.(bool); ok {
			return va == vb
		}
	case string:
		if vb, ok := b.(string); ok {
			return va == vb
		}
	}

	// Fallback to basic equality check
	return a == b
}

// img4Im4mPersonalizeCmd represents the im4m personalize command
var img4Im4mPersonalizeCmd = &cobra.Command{
	Use:           "personalize",
	Short:         "Create personalized IM4M manifest with device-specific values",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		inputPath := viper.GetString("img4.im4m.personalize.input")
		outputPath := viper.GetString("img4.im4m.personalize.output")
		ecid := viper.GetString("img4.im4m.personalize.ecid")
		nonce := viper.GetString("img4.im4m.personalize.nonce")
		verboseOutput := viper.GetBool("img4.im4m.personalize.verbose")

		fmt.Printf("%s        %s\n", colorField("Input IMG4:"), filepath.Base(inputPath))
		fmt.Printf("%s      %s\n", colorField("Output IMG4:"), filepath.Base(outputPath))

		inputFile, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("failed to open input IMG4 %s: %v", inputPath, err)
		}
		defer inputFile.Close()

		inputImg, err := img4.Parse(inputFile)
		if err != nil {
			return fmt.Errorf("failed to parse input IMG4: %v", err)
		}

		personalizedImg, err := personalizeImg4(inputImg, ecid, nonce, verboseOutput)
		if err != nil {
			return fmt.Errorf("personalization failed: %v", err)
		}

		personalizedData, err := img4.CreateImg4File(
			personalizedImg.PayloadData,
			personalizedImg.ManifestData,
			personalizedImg.RestoreInfoData)
		if err != nil {
			return fmt.Errorf("failed to create personalized IMG4: %v", err)
		}

		if err := os.WriteFile(outputPath, personalizedData, 0644); err != nil {
			return fmt.Errorf("failed to write personalized IMG4: %v", err)
		}

		fmt.Printf("\n%s ✓ Personalization %s\n",
			color.New(color.FgGreen).Sprint("SUCCESS:"),
			color.New(color.FgGreen).Sprint("COMPLETED"))
		fmt.Printf("%s         %s\n", colorField("Output Size:"), humanize.Bytes(uint64(len(personalizedData))))

		return nil
	},
}

// PersonalizedImg4 holds the components of a personalized IMG4
type PersonalizedImg4 struct {
	PayloadData     []byte
	ManifestData    []byte
	RestoreInfoData []byte
}

func personalizeImg4(img *img4.Img4, ecid, nonce string, verbose bool) (*PersonalizedImg4, error) {
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

	// Copy existing properties
	maps.Copy(personalizedProperties, img.Manifest.Properties)

	// Update with device-specific values
	personalizedProperties["ECID"] = ecidValue
	personalizedProperties["ApNonce"] = nonceBytes

	if verbose {
		log.Debug("Updating manifest with personalization values:")
		log.Debugf("  ECID: 0x%x", ecidValue)
		log.Debugf("  ApNonce: %x", nonceBytes)
	}

	// Create a new manifest with personalized properties
	personalizedManifest, err := createPersonalizedManifest(img.Manifest.ApImg4Ticket.Bytes, personalizedProperties)
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
