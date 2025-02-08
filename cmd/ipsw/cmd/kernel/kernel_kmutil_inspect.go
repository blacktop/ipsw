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
package kernel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelKmutilCmd.AddCommand(inspectCmd)

	inspectCmd.Flags().BoolP("kernel", "k", false, "Print system kernel path")
	inspectCmd.Flags().StringP("filter", "f", "", "Fitler by bundle ID")
	inspectCmd.Flags().BoolP("explicit-only", "x", false, "Format output to be used as -x arg to kmutil create")
	inspectCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	inspectCmd.Flags().StringP("output", "o", "", "Output folder")
	inspectCmd.MarkFlagDirname("output")
	viper.BindPFlag("kernel.kmutil.inspect.kernel", inspectCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("kernel.kmutil.inspect.filter", inspectCmd.Flags().Lookup("filter"))
	viper.BindPFlag("kernel.kmutil.inspect.explicit-only", inspectCmd.Flags().Lookup("explicit-only"))
	viper.BindPFlag("kernel.kmutil.inspect.json", inspectCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.kmutil.inspect.output", inspectCmd.Flags().Lookup("output"))
}

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:           "inspect",
	Aliases:       []string{"i"},
	Short:         "Inspect and filter a kext collection's contents according to the options provided",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		showKernPath := viper.GetBool("kernel.kmutil.inspect.kernel")
		filter := viper.GetString("kernel.kmutil.inspect.filter")
		explicitOnly := viper.GetBool("kernel.kmutil.inspect.explicit-only")
		asJSON := viper.GetBool("kernel.kmutil.inspect.json")
		outputDir := viper.GetString("kernel.kmutil.inspect.output")
		// validate flags
		if explicitOnly && asJSON {
			return fmt.Errorf("cannot use --explicit-only and --json together")
		}
		if outputDir == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current working directory: %v", err)
			}
			outputDir = cwd
		}

		var kcpath string
		if len(args) < 2 {
			systemKernelCache, err := utils.GetKernelCollectionPath()
			if err != nil {
				return fmt.Errorf("could not find system kernelcache: %v (Please specify path to kernelcache)", err)
			}
			kcpath = systemKernelCache
			if showKernPath {
				fmt.Println(kcpath)
				return nil
			}
		} else {
			kcpath = filepath.Clean(args[1])
		}

		if _, err := os.Stat(kcpath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", kcpath)
		}

		var m *macho.File

		if isImg4(kcpath) {
			log.Info("Decompressing KernelManagement kernelcache")
			data, err := kernelcache.DecompressKernelManagementData(kcpath)
			if err != nil {
				return fmt.Errorf("failed to decompress kernelcache (kernel management data): %v", err)
			}
			m, err = macho.NewFile(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("failed to parse kernelcache (kernel management data): %v", err)
			}
			defer m.Close()
		} else {
			log.Info("Parsing KernelManagement kernelcache")
			m, err = macho.Open(kcpath)
			if err != nil {
				return fmt.Errorf("failed to parse kernelcache MachO: %v", err)
			}
			defer m.Close()
		}

		if m.FileTOC.FileHeader.Type != types.MH_FILESET {
			return fmt.Errorf("kernelcache type is not MH_FILESET (kext collection)")
		}

		out, err := kernelcache.InspectKM(m, filter, explicitOnly, asJSON)
		if err != nil {
			return fmt.Errorf("failed to inspect kernelcache: %v", err)
		}
		fmt.Println(out)

		return nil
	},
}
