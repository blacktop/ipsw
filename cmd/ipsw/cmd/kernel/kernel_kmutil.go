/*
Copyright © 2023 blacktop

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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var kmutilCmdSubCmds = []string{"inspect"}

func init() {
	KernelcacheCmd.AddCommand(kernelKmutilCmd)
	kernelKmutilCmd.Flags().StringP("filter", "f", "", "Fitler by bundle ID")
	kernelKmutilCmd.Flags().BoolP("explicit-only", "x", false, "Format output to be used as -x arg to kmutil create")
	kernelKmutilCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	kernelKmutilCmd.Flags().StringP("output", "o", "", "Output folder")
	viper.BindPFlag("kernel.kmutil.filter", kernelKmutilCmd.Flags().Lookup("filter"))
	viper.BindPFlag("kernel.kmutil.explicit-only", kernelKmutilCmd.Flags().Lookup("explicit-only"))
	viper.BindPFlag("kernel.kmutil.json", kernelKmutilCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.kmutil.output", kernelKmutilCmd.Flags().Lookup("output"))
}

// kernelKmutilCmd represents the kmutil command
var kernelKmutilCmd = &cobra.Command{
	Use:     "kmutil",
	Aliases: []string{"km"},
	Short:   "KernelManagement Utility",
	Args:    cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return kmutilCmdSubCmds, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	},
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		filter := viper.GetString("kernel.kmutil.filter")
		explicitOnly := viper.GetBool("kernel.kmutil.explicit-only")
		asJSON := viper.GetBool("kernel.kmutil.json")
		outputDir := viper.GetString("kernel.kmutil.output")
		// validate flags
		if explicitOnly && asJSON {
			return fmt.Errorf("cannot use --explicit-only and --json together")
		}
		if outputDir == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			outputDir = cwd
		}

		var kcpath string
		if len(args) < 2 {
			systemKernelCache, err := utils.GetKerncachePath()
			if err != nil {
				return fmt.Errorf("could not find system kernelcache: %v (Please specify path to kernelcache)", err)
			}
			kcpath = systemKernelCache
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
				return err
			}
			m, err = macho.NewFile(bytes.NewReader(data))
			if err != nil {
				return err
			}
			defer m.Close()
		} else {
			log.Info("Parsing KernelManagement kernelcache")
			m, err = macho.Open(kcpath)
			if err != nil {
				return err
			}
			defer m.Close()
		}

		if m.FileTOC.FileHeader.Type != types.MH_FILESET {
			return fmt.Errorf("kernelcache type is not MH_FILESET (kext collection)")
		}

		switch args[0] {
		case "inspect":
			out, err := kernelcache.InspectKM(m, filter, explicitOnly, asJSON)
			if err != nil {
				return err
			}
			fmt.Println(out)
		}

		return nil
	},
}
