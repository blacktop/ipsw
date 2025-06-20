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
	Img4Cmd.AddCommand(img4Im4rCmd)

	// Add subcommands to im4r
	img4Im4rCmd.AddCommand(img4Im4rInfoCmd)

	// Info command flags
	img4Im4rInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4Im4rInfoCmd.Flags().BoolP("verbose", "v", false, "Show detailed information")
	img4Im4rInfoCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.im4r.info.json", img4Im4rInfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("img4.im4r.info.verbose", img4Im4rInfoCmd.Flags().Lookup("verbose"))
}

// img4Im4rCmd represents the im4r command group
var img4Im4rCmd = &cobra.Command{
	Use:   "im4r",
	Short: "IM4R restore info operations",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// img4Im4rInfoCmd represents the im4r info command
var img4Im4rInfoCmd = &cobra.Command{
	Use:           "info <IMG4>",
	Short:         "Display IM4R restore information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.im4r.info.json")
		verboseOutput := viper.GetBool("img4.im4r.info.verbose")

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		img, err := img4.Parse(f)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4: %v", err)
		}

		return displayIm4rInfo(img, filePath, jsonOutput, verboseOutput)
	},
}

func displayIm4rInfo(img *img4.Img4, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		data := map[string]interface{}{
			"file":      filepath.Base(filePath),
			"generator": fmt.Sprintf("%x", img.RestoreInfo.Generator.Data),
		}

		if verbose {
			data["raw_restore_info"] = fmt.Sprintf("%x", img.RestoreInfo.Generator.Raw)
		}

		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IM4R info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s      %s\n", colorField("File:"), filepath.Base(filePath))
		fmt.Printf("%s %s\n", colorField("Generator:"), string(img.RestoreInfo.Generator.Data))
		
		if verbose {
			fmt.Printf("%s %x\n", colorField("Generator Data:"), img.RestoreInfo.Generator.Data)
			fmt.Printf("%s       %d bytes\n", colorField("Raw Data:"), len(img.RestoreInfo.Generator.Raw))
		}
	}

	return nil
}