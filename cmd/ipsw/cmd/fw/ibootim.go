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
package fw

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ibootim"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(ibootimCmd)

	ibootimCmd.Flags().BoolP("info", "i", false, "Print info")
	ibootimCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	ibootimCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.ibootim.info", ibootimCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.ibootim.output", ibootimCmd.Flags().Lookup("output"))
}

// ibootimCmd represents the ibootim command
var ibootimCmd = &cobra.Command{
	Use:     "ibootim",
	Aliases: []string{"ibm"},
	Short:   "🚧 Dump iBoot Images",
	Args:    cobra.ExactArgs(1),
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.ibootim.info")
		output := viper.GetString("fw.ibootim.output")

		if ok, _ := magic.IsIm4p(filepath.Clean(args[0])); ok {
			log.Info("Processing IM4P file")
			im4p, err := img4.OpenIm4p(filepath.Clean(args[0]))
			if err != nil {
				return err
			}
			ibm, err := ibootim.Parse(bytes.NewReader(im4p.Data))
			if err != nil {
				return fmt.Errorf("failed to parse ibootim: %v", err)
			}
			if showInfo {
				fmt.Println(ibm.Header)
			} else {
				fname := fmt.Sprintf("%s.png", strings.TrimSuffix(filepath.Base(args[0]), filepath.Ext(filepath.Base(args[0]))))
				if output != "" {
					fname = filepath.Join(output, filepath.Base(fname))
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting iBoot Image to file %s", fname))
				println(ibm.String())
				return ibm.ToPNG(fname)
			}
		} else {
			ibm, err := ibootim.Open(filepath.Clean(args[0]))
			if err != nil {
				return fmt.Errorf("failed to open iBoot Image: %v", err)
			}
			defer ibm.Close()
			if showInfo {
				fmt.Println(ibm.Header)
			} else {
				fname := fmt.Sprintf("%s.png", strings.TrimSuffix(filepath.Base(args[0]), filepath.Ext(filepath.Base(args[0]))))
				if output != "" {
					fname = filepath.Join(output, filepath.Base(fname))
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting iBoot Image to file %s", fname))
				println(ibm.String())
				return ibm.ToPNG(fname)
			}
		}

		return nil
	},
}
