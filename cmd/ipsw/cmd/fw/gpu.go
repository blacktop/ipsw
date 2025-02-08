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
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(gpuCmd)

	gpuCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	gpuCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.gpu.output", gpuCmd.Flags().Lookup("output"))
}

// gpuCmd represents the gpu command
var gpuCmd = &cobra.Command{
	Use:     "gpu",
	Aliases: []string{"agx"},
	Short:   "Dump MachOs",
	Args:    cobra.ExactArgs(1),
	Hidden:  true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if isZip, err := magic.IsZip(filepath.Clean(args[0])); err != nil {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip {
			out, err := extract.Search(&extract.Config{
				IPSW:    filepath.Clean(args[0]),
				Pattern: "armfw_.*.im4p$",
				Output:  viper.GetString("fw.gpu.output"),
			})
			if err != nil {
				return err
			}
			for _, f := range out {
				folder := filepath.Join(filepath.Dir(f), "extracted")
				if _, err := fwcmd.SplitGpuFW(f, folder); err != nil {
					return fmt.Errorf("failed to split GPU firmware: %v", err)
				}
			}
		} else {
			if _, err := fwcmd.SplitGpuFW(filepath.Clean(args[0]), viper.GetString("fw.gpu.output")); err != nil {
				return fmt.Errorf("failed to split GPU firmware: %v", err)
			}
		}

		return nil
	},
}
