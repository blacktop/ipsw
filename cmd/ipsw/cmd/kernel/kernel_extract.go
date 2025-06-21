/*
Copyright © 2018-2025 blacktop

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
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(kerExtractCmd)

	kerExtractCmd.Flags().BoolP("all", "a", false, "Extract all KEXTs")
	kerExtractCmd.Flags().String("output", "", "Directory to extract KEXTs to")
	kerExtractCmd.Flags().StringP("arch", "e", "", "Which architecture to use for fat/universal MachO")

	viper.BindPFlag("kernel.extract.all", kerExtractCmd.Flags().Lookup("all"))
	viper.BindPFlag("kernel.extract.output", kerExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("kernel.extract.arch", kerExtractCmd.Flags().Lookup("arch"))
}

// kerExtractCmd represents the kerExtract command
var kerExtractCmd = &cobra.Command{
	Use:           "extract <KERNELCACHE> <KEXT>",
	Aliases:       []string{"e"},
	Short:         "Extract KEXT(s) from kernelcache",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		dumpAll := viper.GetBool("kernel.extract.all")
		extractPath := viper.GetString("kernel.extract.output")
		selectedArch := viper.GetString("kernel.extract.arch")

		if len(args) == 1 && !dumpAll {
			return fmt.Errorf("you must specify a KEXT to extract OR use the --all flag")
		}

		kernPath := filepath.Clean(args[0])

		if ok, err := magic.IsMachoOrImg4(kernPath); !ok {
			return fmt.Errorf("invalid file format: %v", err)
		}

		folder := filepath.Dir(kernPath)
		if len(extractPath) > 0 {
			folder = extractPath
		}

		m, err := mcmd.OpenMachO(kernPath, selectedArch)
		if err != nil {
			return fmt.Errorf("failed to open kernelcache: %v", err)
		}
		defer m.Close()

		if m.File.FileTOC.FileHeader.Type != types.MH_FILESET {
			return fmt.Errorf("kernelcache type is not MH_FILESET (KEXT-xtraction not supported yet)")
		}

		var dcf *fixupchains.DyldChainedFixups
		if m.File.HasFixups() {
			dcf, err = m.File.DyldChainedFixups()
			if err != nil {
				return fmt.Errorf("failed to parse fixups from in memory MachO: %v", err)
			}
		}

		baseAddress := m.File.GetBaseAddress()

		if dumpAll {
			log.Info("Extracting all KEXTs...")
			for _, fse := range m.File.FileSets() {
				mfse, err := m.File.GetFileSetFileByName(fse.EntryID)
				if err != nil {
					return fmt.Errorf("failed to parse KEXT %s: %v", fse.EntryID, err)
				}
				if err := mfse.Export(filepath.Join(folder, fse.EntryID), dcf, baseAddress, nil); err != nil { // TODO: do I want to add any extra syms?
					return fmt.Errorf("failed to export KEXT %s; %v", fse.EntryID, err)
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", filepath.Join(folder, fse.EntryID)))
			}
		} else {
			mfse, err := m.File.GetFileSetFileByName(args[1])
			if err != nil {
				return fmt.Errorf("failed to parse KEXT %s: %v", args[1], err)
			}

			if err := mfse.Export(filepath.Join(folder, args[1]), dcf, baseAddress, nil); err != nil { // TODO: do I want to add any extra syms?
				return fmt.Errorf("failed to export KEXT %s; %v", args[1], err)
			}
			log.Infof("Created %s", filepath.Join(folder, args[1]))
		}

		return nil
	},
}
