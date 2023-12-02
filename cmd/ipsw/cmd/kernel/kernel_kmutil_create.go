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
	"strings"

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
	KernelKmutilCmd.AddCommand(createCmd)

	createCmd.Flags().StringP("suffix", "s", "release", "The image suffix to use for the kernel variant")
	createCmd.Flags().StringP("arch", "a", "arm64e", "The architecture to use for the extension(s)/collection(s) specified")
	createCmd.Flags().StringP("kernel", "k", "", "Input kernel")
	createCmd.Flags().StringP("filter", "f", "", "Fitler by bundle ID")
	viper.BindPFlag("kernel.kmutil.create.suffix", createCmd.Flags().Lookup("suffix"))
	viper.BindPFlag("kernel.kmutil.create.arch", createCmd.Flags().Lookup("arch"))
	viper.BindPFlag("kernel.kmutil.create.kernel", createCmd.Flags().Lookup("kernel"))
	viper.BindPFlag("kernel.kmutil.create.filter", createCmd.Flags().Lookup("filter"))
}

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:           "create <KC_OUT>",
	Aliases:       []string{"c"},
	Short:         "Create one or more new artifacts based on the arguments provided",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		var kcpath string
		if len(args) < 2 {
			systemKernelCache, err := utils.GetKernelCollectionPath()
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

		var exclude []string
		if len(viper.GetString("kernel.kmutil.create.filter")) > 0 {
			out, err := kernelcache.InspectKM(m, viper.GetString("kernel.kmutil.create.filter"), true, false)
			if err != nil {
				return fmt.Errorf("failed to inspect kernelcache: %v", err)
			}
			exclude = strings.Split(out, " ")
		}

		return utils.KmutilCreate(&utils.KMUConfig{
			Suffix:  viper.GetString("kernel.kmutil.create.suffix"),
			Arch:    viper.GetString("kernel.kmutil.create.arch"),
			Name:    args[0],
			Kernel:  viper.GetString("kernel.kmutil.create.kernel"),
			Exclude: exclude,
		})
	},
}
