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
	"path/filepath"

	"github.com/apex/log"
	icmd "github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4ExtractCmd)

	img4ExtractCmd.Flags().Bool("img4", false, "Input file is an IMG4")
	img4ExtractCmd.Flags().StringP("output", "o", "", "Output folder")
	img4ExtractCmd.MarkFlagDirname("output")
	viper.BindPFlag("img4.extract.img4", img4DecCmd.Flags().Lookup("img4"))
	viper.BindPFlag("img4.extract.output", img4DecCmd.Flags().Lookup("output"))
	img4ExtractCmd.MarkZshCompPositionalArgumentFile(1)
}

// img4ExtractCmd represents the extract command
var img4ExtractCmd = &cobra.Command{
	Use:     "extract <im4p>",
	Aliases: []string{"e"},
	Short:   "Extract im4p payloads",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")
		// flags
		isImg4 := viper.GetBool("img4.extract.img4")
		outputDir := viper.GetString("img4.extract.output")

		outFile := filepath.Clean(args[0]) + ".payload"
		if outputDir != "" {
			outFile = filepath.Join(outputDir, outFile)
		}

		utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting payload to file %s", outFile))
		return icmd.ExtractPayload(filepath.Clean(args[0]), outFile, isImg4)
	},
}
