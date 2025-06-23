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
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4InfoCmd)
	img4InfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	img4InfoCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.info.json", img4InfoCmd.Flags().Lookup("json"))
}

// img4InfoCmd represents the info command
var img4InfoCmd = &cobra.Command{
	Use:           "info <IMG4>",
	Aliases:       []string{"i"},
	Short:         "Display IMG4 file information",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		filePath := args[0]
		jsonOutput := viper.GetBool("img4.info.json")

		isImg4, err := magic.IsImg4(filePath)
		if err != nil {
			return fmt.Errorf("failed to determine file type: %v", err)
		}

		if !isImg4 {
			return fmt.Errorf("file is not an IMG4 file (for IM4P files, use 'ipsw img4 im4p info')")
		}

		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer f.Close()

		img, err := img4.Parse(f)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4 file: %v", err)
		}
		return displayImg4Info(img, filePath, jsonOutput, viper.GetBool("verbose"))
	},
}

func displayImg4Info(img *img4.Img4, filePath string, jsonOutput, verbose bool) error {
	if jsonOutput {
		data := map[string]any{
			"file":         filepath.Base(filePath),
			"type":         "IMG4",
			"name":         img.Name,
			"description":  img.Description,
			"manifest":     img.Manifest,
			"restore_info": img.RestoreInfo,
		}
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal IMG4 info: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("%s             IMG4\n", colorField("Type:"))
		fmt.Printf("%s             %s\n", colorField("Name:"), img.Name)
		if len(img.Description) > 0 {
			fmt.Printf("%s      %s\n", colorField("Description:"), img.Description)
		}
		if verbose {
			if len(img.Manifest.Properties) > 0 {
				fmt.Printf("%s\n", colorField("Manifest Properties:"))
				for key, value := range img.Manifest.Properties {
					fmt.Printf("  %s: %v\n", colorSubField(key), value)
				}
			}
			if len(img.RestoreInfo.Generator.Data) > 0 {
				fmt.Printf("%s\n", colorField("Restore Info:"))
				fmt.Printf("  %s %x\n", colorSubField("Generator:"), img.RestoreInfo.Generator.Data)
			}
		}
	}

	return nil
}
