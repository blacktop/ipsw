/*
Copyright © 2018-2026 blacktop

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
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// resolveImports resolves a KEXT's undefined symbols against the parent
// kernelcache's symbol table, returning them as defined symbols suitable
// for injection into the KEXT's own symbol table during export.
func resolveImports(kext *macho.File, kcSymMap map[string]macho.Symbol) []macho.Symbol {
	if kext.Symtab == nil || kcSymMap == nil {
		return nil
	}
	var resolved []macho.Symbol
	for _, sym := range kext.Symtab.Syms {
		if sym.Type.IsUndefinedSym() && sym.Name != "" {
			if kcSym, ok := kcSymMap[sym.Name]; ok {
				resolved = append(resolved, macho.Symbol{
					Name:  sym.Name,
					Type:  types.N_ABS | types.N_EXT,
					Sect:  0,
					Desc:  sym.Desc,
					Value: kcSym.Value,
				})
			}
		}
	}
	return resolved
}

func init() {
	KernelcacheCmd.AddCommand(kerExtractCmd)

	kerExtractCmd.Flags().BoolP("all", "a", false, "Extract all KEXTs")
	kerExtractCmd.Flags().Bool("force", false, "Overwrite existing extracted KEXT(s)")
	kerExtractCmd.Flags().Bool("imports", false, "Resolve imported symbol names from kernelcache")
	kerExtractCmd.Flags().StringP("output", "o", "", "Directory to extract KEXTs to")
	kerExtractCmd.MarkFlagDirname("output")
	kerExtractCmd.Flags().StringP("arch", "e", "", "Which architecture to use for fat/universal MachO")

	viper.BindPFlag("kernel.extract.all", kerExtractCmd.Flags().Lookup("all"))
	viper.BindPFlag("kernel.extract.force", kerExtractCmd.Flags().Lookup("force"))
	viper.BindPFlag("kernel.extract.imports", kerExtractCmd.Flags().Lookup("imports"))
	viper.BindPFlag("kernel.extract.output", kerExtractCmd.Flags().Lookup("output"))
	viper.BindPFlag("kernel.extract.arch", kerExtractCmd.Flags().Lookup("arch"))
}

// kerExtractCmd represents the kerExtract command
var kerExtractCmd = &cobra.Command{
	Use:           "extract <KERNELCACHE> <KEXT>",
	Aliases:       []string{"e"},
	Short:         "Extract KEXT(s) from kernelcache",
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		dumpAll := viper.GetBool("kernel.extract.all")
		forceExtract := viper.GetBool("kernel.extract.force")
		addImports := viper.GetBool("kernel.extract.imports")
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
			return fmt.Errorf("kernelcache type is not MH_FILESET (KEXT extraction not supported yet)")
		}

		var dcf *fixupchains.DyldChainedFixups
		if m.File.HasFixups() {
			dcf, err = m.File.DyldChainedFixups()
			if err != nil {
				return fmt.Errorf("failed to parse fixups from in memory MachO: %v", err)
			}
		}

		baseAddress := m.File.GetBaseAddress()

		// build a name→symbol map of all defined symbols across all fileset
		// entries for resolving imported symbols in extracted KEXTs
		var kcSymMap map[string]macho.Symbol
		if addImports {
			kcSymMap = make(map[string]macho.Symbol)
			log.Info("Building kernelcache symbol map...")
			for _, fse := range m.File.FileSets() {
				mfse, err := m.File.GetFileSetFileByName(fse.EntryID)
				if err != nil {
					continue
				}
				if mfse.Symtab != nil {
					for _, sym := range mfse.Symtab.Syms {
						if sym.Type.IsExternalSym() && !sym.Type.IsUndefinedSym() && sym.Value != 0 {
							kcSymMap[sym.Name] = sym
						}
					}
				}
			}
			log.Infof("Built kernelcache symbol map (%d defined symbols)", len(kcSymMap))
		}

		if dumpAll {
			log.Info("Extracting all KEXTs...")
			for _, fse := range m.File.FileSets() {
				fname := filepath.Join(folder, fse.EntryID)
				if _, err := os.Stat(fname); err == nil && !forceExtract {
					utils.Indent(log.Warn, 2)(fmt.Sprintf("KEXT already exists: %s (use --force to overwrite)", fname))
					continue
				} else if err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("failed to stat %s: %w", fname, err)
				}
				mfse, err := m.File.GetFileSetFileByName(fse.EntryID)
				if err != nil {
					return fmt.Errorf("failed to parse KEXT %s: %v", fse.EntryID, err)
				}
				syms := resolveImports(mfse, kcSymMap)
				if err := mfse.Export(fname, dcf, baseAddress, syms); err != nil {
					return fmt.Errorf("failed to export KEXT %s: %v", fse.EntryID, err)
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", fname))
			}
		} else {
			fname := filepath.Join(folder, args[1])
			if _, err := os.Stat(fname); err == nil && !forceExtract {
				log.Warnf("KEXT already exists: %s (use --force to overwrite)", fname)
				return nil
			} else if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to stat %s: %w", fname, err)
			}
			mfse, err := m.File.GetFileSetFileByName(args[1])
			if err != nil {
				return fmt.Errorf("failed to parse KEXT %s: %v", args[1], err)
			}
			syms := resolveImports(mfse, kcSymMap)
			if err := mfse.Export(fname, dcf, baseAddress, syms); err != nil {
				return fmt.Errorf("failed to export KEXT %s: %v", args[1], err)
			}
			log.Infof("Created %s", fname)
		}

		return nil
	},
}
