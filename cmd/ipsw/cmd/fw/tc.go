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
	"github.com/blacktop/ipsw/internal/commands/extract"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NOTE:
//   Firmware/044-09543-048.dmg.trustcache
//   Firmware/044-36267-012.dmg.aea.trustcache

func init() {
	FwCmd.AddCommand(tcCmd)

	tcCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	tcCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.tc.output", tcCmd.Flags().Lookup("output"))
}

// tcCmd represents the tc command
var tcCmd = &cobra.Command{
	Use:   "tc <IM4P|IPSW>",
	Short: "🚧 Dump TrustCache",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if isZip, err := magic.IsZip(filepath.Clean(args[0])); err != nil {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip {
			out, err := extract.Search(&extract.Config{
				IPSW:    filepath.Clean(args[0]),
				Pattern: ".trustcache$",
				Output:  viper.GetString("fw.tc.output"),
			})
			if err != nil {
				return err
			}
			for _, f := range out {
				if ok, _ := magic.IsIm4p(f); ok {
					log.WithField("file", f).Info("Processing IM4P file")
					im4p, err := img4.OpenIm4p(f)
					if err != nil {
						return err
					}
					tc, err := fwcmd.ParseTrustCache(im4p.Data)
					if err != nil {
						return fmt.Errorf("failed to parse trust cache: %v", err)
					}
					fmt.Println(tc)
				} else {
					return fmt.Errorf("unsupported file type: expected IM4P")
				}
			}
		} else {
			if ok, _ := magic.IsIm4p(filepath.Clean(args[0])); ok {
				log.WithField("file", filepath.Clean(args[0])).Info("Processing IM4P file")
				im4p, err := img4.OpenIm4p(filepath.Clean(args[0]))
				if err != nil {
					return err
				}
				tc, err := fwcmd.ParseTrustCache(im4p.Data)
				if err != nil {
					return fmt.Errorf("failed to parse trust cache: %v", err)
				}
				fmt.Println(tc)
			} else {
				return fmt.Errorf("unsupported file type: expected IM4P")
			}
		}

		return nil
	},
}
