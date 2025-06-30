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

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/img4"
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
	Use:     "info <IMG4>",
	Aliases: []string{"i"},
	Short:   "Display IMG4 file information",
	Example: heredoc.Doc(`
		# Display information about an IMG4 file
		❯ ipsw img4 info kernel.img4

		# Output information as JSON
		❯ ipsw img4 info --json kernel.img4`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		infile := filepath.Clean(args[0])

		isImg4, err := magic.IsImg4(infile)
		if err != nil {
			return fmt.Errorf("failed to determine file type: %v", err)
		}

		if !isImg4 {
			return fmt.Errorf("file is not an IMG4 file (for IM4P files, use 'ipsw img4 im4p info')")
		}

		img, err := img4.Open(infile)
		if err != nil {
			return fmt.Errorf("failed to parse IMG4 file: %v", err)
		}

		if viper.GetBool("img4.info.json") {
			json, err := img.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal IMG4 file: %v", err)
			}
			fmt.Println(string(json))
		} else {
			fmt.Println(img)
		}

		return nil
	},
}
