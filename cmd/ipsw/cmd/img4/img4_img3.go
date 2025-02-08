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
	"path/filepath"

	"github.com/apex/log"
	icmd "github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4Img3Cmd)

	img4Img3Cmd.Flags().StringP("output", "o", "", "Output folder")
	img4Img3Cmd.MarkFlagDirname("output")
	viper.BindPFlag("img4.img3.output", img4Img3Cmd.Flags().Lookup("output"))

	img4Img3Cmd.MarkZshCompPositionalArgumentFile(1)
}

// img4Img3Cmd represents the extract command
var img4Img3Cmd = &cobra.Command{
	Use:     "img3 <img3>",
	Aliases: []string{"3"},
	Short:   "Extract img3 payloads",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		outputDir := viper.GetString("img4.dec.output")

		outFile := filepath.Clean(args[0]) + ".payload"
		if outputDir != "" {
			outFile = filepath.Join(outputDir, outFile)
		}

		log.Infof("Extracting payload to file %s", outFile)
		return icmd.ParseImg3(filepath.Clean(args[0]), outFile)
	},
}
