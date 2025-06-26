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
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ibootim"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//	Firmware/all_flash/applelogo@3x-style0~iphone.im4p
//	Firmware/all_flash/liquiddetect@2622~iphone-USBc-woven.im4p
//	Firmware/all_flash/recoverymode@2622~iphone-USBc-woven.im4p

func init() {
	FwCmd.AddCommand(ibootimCmd)

	ibootimCmd.Flags().BoolP("info", "i", false, "Print info")
	ibootimCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	ibootimCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when extracting im4p files")
	ibootimCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	ibootimCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.ibootim.info", ibootimCmd.Flags().Lookup("info"))
	viper.BindPFlag("fw.ibootim.remote", ibootimCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.ibootim.flat", ibootimCmd.Flags().Lookup("flat"))
	viper.BindPFlag("fw.ibootim.output", ibootimCmd.Flags().Lookup("output"))
}

// ibootimCmd represents the ibootim command
var ibootimCmd = &cobra.Command{
	Use:           "ibootim",
	Aliases:       []string{"ibm"},
	Short:         "Dump iBoot Images",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showInfo := viper.GetBool("fw.ibootim.info")
		flat := viper.GetBool("fw.ibootim.flat")
		output := viper.GetString("fw.ibootim.output")

		infile := filepath.Clean(args[0])
		cwd, _ := os.Getwd()

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.ibootim.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.ibootim.remote") {
			var out []string
			if viper.GetBool("fw.ibootim.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: "(~iphone|~ipad|~mac|~watch|~appletv|~reality).*\\.im4p$",
					Flatten: flat,
					Output:  output,
				})
				if err != nil {
					return fmt.Errorf("failed to search for ibootim in remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: "(~iphone|~ipad|~mac|~watch|~appletv|~reality).*\\.im4p$",
					Flatten: flat,
					Output:  output,
				})
				if err != nil {
					return fmt.Errorf("failed to search for ibootim in local IPSW: %v", err)
				}
			}
			for _, f := range out {
				if ok, _ := magic.IsIm4p(f); ok {
					log.Infof("Processing IM4P file: %s", filepath.Base(f))
					im4p, err := img4.OpenPayload(f)
					if err != nil {
						return err
					}
					ibm, err := ibootim.Parse(bytes.NewReader(im4p.Data))
					if err != nil {
						return fmt.Errorf("failed to parse ibootim: %v", err)
					}
					if showInfo {
						fmt.Println(ibm.String())
					} else {
						outs, err := ibm.ToPNG(f, filepath.Dir(f))
						if err != nil {
							return fmt.Errorf("failed to extract iBoot Image(s): %v", err)
						}
						for _, out := range outs {
							utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting iBoot Image to file %s", strings.TrimPrefix(out, cwd+"/")))
						}
					}
				}
				os.Remove(f) // remove the extracted im4p file
			}
		} else if ok, _ := magic.IsIm4p(infile); ok {
			log.Info("Processing IM4P file")
			im4p, err := img4.OpenPayload(infile)
			if err != nil {
				return err
			}
			ibm, err := ibootim.Parse(bytes.NewReader(im4p.Data))
			if err != nil {
				return fmt.Errorf("failed to parse ibootim: %v", err)
			}
			if showInfo {
				fmt.Println(ibm.String())
			} else {
				outs, err := ibm.ToPNG(infile, output)
				if err != nil {
					return fmt.Errorf("failed to extract iBoot Image(s): %v", err)
				}
				for _, out := range outs {
					utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting iBoot Image to file %s", strings.TrimPrefix(out, cwd+"/")))
				}
			}
		} else {
			ibm, err := ibootim.Open(infile)
			if err != nil {
				return fmt.Errorf("failed to open iBoot Image: %v", err)
			}
			defer ibm.Close()
			if showInfo {
				fmt.Println(ibm.String())
			} else {
				outs, err := ibm.ToPNG(infile, output)
				if err != nil {
					return fmt.Errorf("failed to extract iBoot Image(s): %v", err)
				}
				for _, out := range outs {
					utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting iBoot Image to file %s", strings.TrimPrefix(out, cwd+"/")))
				}
			}
		}

		return nil
	},
}
