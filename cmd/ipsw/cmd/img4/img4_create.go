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
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4CreateCmd)

	img4CreateCmd.Flags().StringP("payload", "p", "", "IM4P payload file (required)")
	img4CreateCmd.Flags().StringP("manifest", "m", "", "IM4M manifest file")
	img4CreateCmd.Flags().StringP("restore-info", "r", "", "IM4R restore info file")
	img4CreateCmd.Flags().StringP("output", "o", "", "Output IMG4 file path")
	img4CreateCmd.MarkFlagRequired("payload")
	img4CreateCmd.MarkFlagFilename("payload")
	img4CreateCmd.MarkFlagFilename("manifest")
	img4CreateCmd.MarkFlagFilename("restore-info")
	img4CreateCmd.MarkFlagFilename("output")

	viper.BindPFlag("img4.create.payload", img4CreateCmd.Flags().Lookup("payload"))
	viper.BindPFlag("img4.create.manifest", img4CreateCmd.Flags().Lookup("manifest"))
	viper.BindPFlag("img4.create.restore-info", img4CreateCmd.Flags().Lookup("restore-info"))
	viper.BindPFlag("img4.create.output", img4CreateCmd.Flags().Lookup("output"))
}

// img4CreateCmd represents the create command
var img4CreateCmd = &cobra.Command{
	Use:           "create",
	Short:         "Create IMG4 file from components",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		payloadPath := viper.GetString("img4.create.payload")
		manifestPath := viper.GetString("img4.create.manifest")
		restoreInfoPath := viper.GetString("img4.create.restore-info")
		outputPath := viper.GetString("img4.create.output")

		// Set default output path if not specified
		if outputPath == "" {
			outputPath = filepath.Clean(payloadPath) + ".img4"
		}

		return createImg4(payloadPath, manifestPath, restoreInfoPath, outputPath)
	},
}

func createImg4(payloadPath, manifestPath, restoreInfoPath, outputPath string) error {
	payloadData, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read payload file: %v", err)
	}

	var manifestData []byte
	var restoreInfoData []byte

	// Read manifest file if provided
	if manifestPath != "" {
		manifestData, err = os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest file: %v", err)
		}
	}

	// Read restore info file if provided
	if restoreInfoPath != "" {
		restoreInfoData, err = os.ReadFile(restoreInfoPath)
		if err != nil {
			return fmt.Errorf("failed to read restore info file: %v", err)
		}
	}

	img4Data, err := img4.CreateImg4File(payloadData, manifestData, restoreInfoData)
	if err != nil {
		return fmt.Errorf("failed to create IMG4: %v", err)
	}

	if err := os.WriteFile(outputPath, img4Data, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	fmt.Printf("%s       %s\n", colorField("Payload:"), filepath.Base(payloadPath))
	if manifestPath != "" {
		fmt.Printf("%s      %s\n", colorField("Manifest:"), filepath.Base(manifestPath))
	}
	if restoreInfoPath != "" {
		fmt.Printf("%s  %s\n", colorField("Restore Info:"), filepath.Base(restoreInfoPath))
	}
	fmt.Printf("%s        %s\n", colorField("Output:"), outputPath)
	fmt.Printf("%s      %s\n", colorField("IMG4 Size:"), humanize.Bytes(uint64(len(img4Data))))

	return nil
}
