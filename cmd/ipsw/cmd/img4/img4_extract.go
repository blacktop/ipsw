/*
Copyright © 2018-2024 blacktop

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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4ExtractCmd)

	img4ExtractCmd.Flags().Bool("img4", false, "Input file is an IMG4")
	img4ExtractCmd.Flags().StringP("output", "o", "", "Output file")
	img4ExtractCmd.MarkZshCompPositionalArgumentFile(1)
}

// img4ExtractCmd represents the extract command
var img4ExtractCmd = &cobra.Command{
	Use:     "extract <im4p>",
	Aliases: []string{"e"},
	Short:   "Extract im4p payloads",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		isImg4, _ := cmd.Flags().GetBool("img4")
		outputDir, _ := cmd.Flags().GetString("output")

		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open file: %s", err)
		}
		defer f.Close()

		var dat []byte

		if isImg4 {
			i, err := img4.ParseImg4(f)
			if err != nil {
				return fmt.Errorf("failed to parse IMG4: %s", err)
			}
			dat = i.IM4P.Data
		} else {
			i, err := img4.ParseIm4p(f)
			if err != nil {
				return fmt.Errorf("failed to parse IM4P: %s", err)
			}
			dat = i.Data
		}

		outFile := filepath.Join(outputDir, args[0]+".payload")
		os.MkdirAll(filepath.Dir(outFile), 0755)

		utils.Indent(log.Info, 2)(fmt.Sprintf("Exracting payload to file %s", outFile))

		if bytes.Contains(dat[:4], []byte("bvx2")) {
			utils.Indent(log.Debug, 2)("Detected LZFSE compression")
			dat, err := lzfse.NewDecoder(dat).DecodeBuffer()
			if err != nil {
				return fmt.Errorf("failed to lzfse decompress %s: %v", args[0], err)
			}

			err = os.WriteFile(outFile, dat, 0660)
			if err != nil {
				return fmt.Errorf("failed to write file %s: %v", outFile, err)
			}
		} else {
			err = os.WriteFile(outFile, dat, 0660)
			if err != nil {
				return fmt.Errorf("failed to write file %s: %v", outFile, err)
			}
		}

		return nil
	},
}
