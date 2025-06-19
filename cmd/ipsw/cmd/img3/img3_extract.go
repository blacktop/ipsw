/*
Copyright © 2025 blacktop

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
package img3

import (
	"fmt"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img3"
	"github.com/spf13/cobra"
)

func init() {
	Img3Cmd.AddCommand(img3ExtractCmd)

	img3ExtractCmd.Flags().StringP("output", "o", "", "Output file for decrypted data")
}

// img3ExtractCmd represents the extract command
var img3ExtractCmd = &cobra.Command{
	Use:          "extract",
	Short:        "Extract data from img3 files",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		outputFile, _ := cmd.Flags().GetString("output")

		data, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", args[0], err)
		}

		img3File, err := img3.ParseImg3(data)
		if err != nil {
			return fmt.Errorf("failed to parse img3 file %s: %v", args[0], err)
		}

		if outputFile == "" {
			outputFile = strings.TrimSuffix(args[0], ".img3") + ".payload"
			if !strings.HasSuffix(args[0], ".img3") {
				outputFile = args[0] + ".payload"
			}
		}

		data, err = img3File.GetDataTag()
		if err != nil {
			return fmt.Errorf("failed to get data tag from img3 file %s: %v", args[0], err)
		}

		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write decrypted data to %s: %v", outputFile, err)
		}

		log.Infof("Data written to: %s", outputFile)

		return nil
	},
}
