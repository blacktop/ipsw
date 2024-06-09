/*
Copyright © 2024 blacktop

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
package fw

import (
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/AOP/aopfw-iphone16aop.RELEASE.im4p

func init() {
	FwCmd.AddCommand(aopCmd)

	aopCmd.Flags().BoolP("info", "i", false, "Print info")
	aopCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	aopCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.aop.info", aopCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.aop.output", aopCmd.Flags().Lookup("output"))
}

// aopCmd represents the aop command
var aopCmd = &cobra.Command{
	Use:    "aop",
	Short:  "🚧 Dump MachOs",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.aop.info")
		// output := viper.GetString("fw.aop.output")

		if showInfo {
			if ok, _ := magic.IsMachO(args[0]); ok { /* MachO binary */
				m, err := macho.Open(filepath.Clean(args[0]))
				if err != nil {
					return fmt.Errorf("failed to parse MachO file: %v", err)
				}
				defer m.Close()
				fmt.Println(m.FileTOC.String())
			} else {
				bn, err := bundle.Parse(filepath.Clean(args[0]))
				if err != nil {
					return err
				}
				fmt.Println(bn)
			}
		} else {
			panic("not implemented")
		}

		return nil
	},
}
