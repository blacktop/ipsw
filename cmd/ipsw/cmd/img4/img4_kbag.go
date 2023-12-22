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
	Img4Cmd.AddCommand(img4KbagCmd)
	img4KbagCmd.Flags().BoolP("json", "j", false, "Extract as JSON")
	img4KbagCmd.MarkZshCompPositionalArgumentFile(1)

	viper.BindPFlag("img4.kbag.json", img4KbagCmd.Flags().Lookup("json"))
}

// img4KbagCmd represents the kbag command
var img4KbagCmd = &cobra.Command{
	Use:           "kbag <IMG4>",
	Aliases:       []string{"k"},
	Short:         "Extract kbag from img4",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", args[0], err)
		}
		defer f.Close()

		log.Info("Parsing Im4p")

		i, err := img4.ParseIm4p(f)
		if err != nil {
			return fmt.Errorf("failed to parse img4: %v", err)
		}

		if viper.GetBool("img4.kbag.json") {
			dat, err := json.Marshal(&struct {
				Name        string        `json:"name,omitempty"`
				Description string        `json:"description,omitempty"`
				Keybags     []img4.Keybag `json:"keybags,omitempty"`
			}{
				Name:        filepath.Base(args[0]),
				Description: i.Description,
				Keybags:     i.Kbags,
			})
			if err != nil {
				return fmt.Errorf("failed to marshal im4g kbag: %v", err)
			}
			fmt.Println(string(dat))
		} else {
			fmt.Println("Keybags:")
			for _, kb := range i.Kbags {
				fmt.Println(kb)
			}
		}

		return nil
	},
}
