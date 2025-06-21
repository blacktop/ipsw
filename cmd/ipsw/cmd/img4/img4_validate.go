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
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4ValidateCmd)
	img4ValidateCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4ValidateCmd.Flags().BoolP("verbose", "v", false, "Show detailed validation information")
	img4ValidateCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.validate.json", img4ValidateCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.validate.verbose", img4ValidateCmd.Flags().Lookup("verbose"))
}

// img4ValidateCmd represents the validate command
var img4ValidateCmd = &cobra.Command{
	Use:           "validate <IMG4>",
	Aliases:       []string{"check"},
	Short:         "Validate IMG4 file structure and integrity",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.validate.json")
		verboseOutput := viper.GetBool("img4.validate.verbose")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		result, err := img4.ValidateImg4Structure(f)
		if err != nil {
			return fmt.Errorf("validation error: %v", err)
		}

		return displayValidationResult(result, filePath, jsonOutput, verboseOutput)
	},
}

func displayValidationResult(result *img4.ValidationResult, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		output := map[string]any{
			"file":       filepath.Base(filePath),
			"structure":  result.Structure,
			"valid":      result.IsValid,
			"components": result.Components,
		}

		if len(result.Errors) > 0 {
			output["errors"] = result.Errors
		}

		if len(result.Warnings) > 0 {
			output["warnings"] = result.Warnings
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal validation result to JSON: %w", err)
		}

		fmt.Println(string(jsonData))
		return nil
	}

	fmt.Printf("%s        %s\n", colorField("File:"), filepath.Base(filePath))
	fmt.Printf("%s    %s\n", colorField("Structure:"), result.Structure)

	if result.IsValid {
		fmt.Printf("%s      %s ✓\n",
			colorField("Status:"),
			color.New(color.FgGreen).Sprint("VALID"))
	} else {
		fmt.Printf("%s      %s ✗\n",
			colorField("Status:"),
			color.New(color.FgRed).Sprint("INVALID"))
	}

	fmt.Printf("%s   %s\n", colorField("Components:"), fmt.Sprintf("%d found", len(result.Components)))
	if verbose && len(result.Components) > 0 {
		for _, component := range result.Components {
			fmt.Printf("  - %s\n", component)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Printf("\n%s\n", color.New(color.FgRed, color.Bold).Sprint("ERRORS:"))
		for _, err := range result.Errors {
			fmt.Printf("  ✗ %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Printf("\n%s\n", color.New(color.FgYellow, color.Bold).Sprint("WARNINGS:"))
		for _, warning := range result.Warnings {
			fmt.Printf("  ⚠ %s\n", warning)
		}
	}

	return nil
}
