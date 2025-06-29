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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
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
	img4Im4mPersonalizeCmd.Flags().StringP("manifest", "m", "", "IM4M manifest file (from TSS response)")
	img4Im4mPersonalizeCmd.Flags().StringP("restore-info", "r", "", "IM4R restore info file (optional)")
	img4Im4mPersonalizeCmd.MarkFlagRequired("output")
	img4Im4mPersonalizeCmd.MarkFlagRequired("manifest")
	img4Im4mPersonalizeCmd.MarkFlagFilename("output")
	img4Im4mPersonalizeCmd.MarkFlagFilename("manifest")
	img4Im4mPersonalizeCmd.MarkFlagFilename("restore-info")
	viper.BindPFlag("img4.im4m.personalize.output", img4Im4mPersonalizeCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.im4m.personalize.manifest", img4Im4mPersonalizeCmd.Flags().Lookup("manifest"))
	viper.BindPFlag("img4.im4m.personalize.restore-info", img4Im4mPersonalizeCmd.Flags().Lookup("restore-info"))
}

// img4Im4mCmd represents the im4m command group
var img4Im4mCmd = &cobra.Command{
	Use:     "im4m",
	Aliases: []string{"m"},
	Short:   "IM4M manifest operations",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4mInfoCmd represents the im4m info command
var img4Im4mInfoCmd = &cobra.Command{
	Use:     "info <IM4M>",
	Aliases: []string{"i"},
	Short:   "Display IM4M manifest information",
	Example: heredoc.Doc(`
		# Display IM4M manifest information
		❯ ipsw img4 im4m info manifest.im4m

		# Output as JSON
		❯ ipsw img4 im4m info --json manifest.im4m`),
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

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
	Use:     "extract <IM4M>",
	Aliases: []string{"e"},
	Short:   "Extract IM4M manifest from SHSH blob",
	Example: heredoc.Doc(`
		# Extract IM4M from SHSH blob
		❯ ipsw img4 im4m extract shsh.blob

		# Extract update manifest (if available)
		❯ ipsw img4 im4m extract --update shsh.blob

		# Extract no-nonce manifest (if available)
		❯ ipsw img4 im4m extract --no-nonce shsh.blob

		# Extract to specific output file
		❯ ipsw img4 im4m extract --output custom.im4m shsh.blob`),
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

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

		log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(manifestData))),
		}).Info("Extracting IM4M")

		return os.WriteFile(outputPath, manifestData, 0644)
	},
}

// img4Im4mVerifyCmd represents the im4m verify command
var img4Im4mVerifyCmd = &cobra.Command{
	Use:   "verify <IM4M>",
	Short: "🚧 Verify IM4M manifest against build manifest",
	Example: heredoc.Doc(`
		# Verify IM4M against build manifest
		❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist manifest.im4m

		# Allow extra properties in IM4M
		❯ ipsw img4 im4m verify --build-manifest BuildManifest.plist --allow-extra manifest.im4m`),
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

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
	Use:   "personalize <IMG4>",
	Short: "Create personalized IMG4 with TSS manifest",
	Example: heredoc.Doc(`
	# Personalize IMG4 with TSS manifest
	❯ ipsw img4 im4m personalize --manifest tss_manifest.im4m --output personalized.img4 kernel.img4
	
	# Personalize with TSS manifest and restore info
	❯ ipsw img4 im4m personalize --manifest tss_manifest.im4m --restore-info restore.im4r --output personalized.img4 kernel.img4`),
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		outputPath := viper.GetString("img4.im4m.personalize.output")
		manifestPath := viper.GetString("img4.im4m.personalize.manifest")
		restoreInfoPath := viper.GetString("img4.im4m.personalize.restore-info")

		infile := filepath.Clean(args[0])

		// Read the input IMG4
		inputImg, err := img4.Open(infile)
		if err != nil {
			return fmt.Errorf("failed to parse input IMG4: %v", err)
		}

		// Read the TSS manifest
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest file: %v", err)
		}

		// Optionally read restore info
		var restoreInfoData []byte
		if restoreInfoPath != "" {
			restoreInfoData, err = os.ReadFile(restoreInfoPath)
			if err != nil {
				return fmt.Errorf("failed to read restore info file: %v", err)
			}
		}

		// Get payload data from the input IMG4
		var payloadData []byte
		if inputImg.Payload != nil {
			payloadData = inputImg.Payload.IM4P.Raw
		} else {
			return fmt.Errorf("input IMG4 has no payload")
		}

		// Create personalized IMG4
		personalizedImg, err := img4.Create(&img4.CreateConfig{
			PayloadData:     payloadData,
			ManifestData:    manifestData,
			RestoreInfoData: restoreInfoData,
		})
		if err != nil {
			return fmt.Errorf("failed to create personalized IMG4: %v", err)
		}

		personalizedData, err := personalizedImg.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal personalized IMG4: %v", err)
		}

		if err := os.WriteFile(outputPath, personalizedData, 0644); err != nil {
			return fmt.Errorf("failed to write personalized IMG4: %v", err)
		}

		log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(personalizedData))),
		}).Info("Personalized IMG4 created successfully")

		return nil
	},
}
