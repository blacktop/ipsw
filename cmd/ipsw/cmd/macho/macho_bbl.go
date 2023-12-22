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
package macho

import (
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoBblCmd)
	machoBblCmd.Flags().String("output", "", "Path to output the universal/fat MachO")
	viper.BindPFlag("macho.bbl.output", machoBblCmd.Flags().Lookup("output"))
	machoBblCmd.MarkFlagRequired("output")
}

// machoBblCmd represents the macho bbl command
var machoBblCmd = &cobra.Command{
	Use:     "bbl <[MACHO]...>",
	Aliases: []string{"b"},
	Short:   "Create single universal/fat MachO out many MachOs",
	Args:    cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		if err := os.MkdirAll(filepath.Dir(viper.GetString("macho.bbl.output")), 0755); err != nil {
			return err
		}

		fat, err := macho.CreateFat(viper.GetString("macho.bbl.output"), args...)
		if err != nil {
			return err
		}
		defer fat.Close()

		_ = fat

		return nil
	},
}
