//go:build unicorn

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
package dyld

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/emu"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(dyldEmuCmd)

	dyldEmuCmd.Flags().StringP("sym", "s", "", "Function to start disassembling")
	dyldEmuCmd.Flags().Uint64P("addr", "a", 0, "Virtual address to start disassembling")
	dyldEmuCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	dyldEmuCmd.Flags().StringP("state", "t", "", "Path to initial state file")
	viper.BindPFlag("dyld.emu.sym", dyldEmuCmd.Flags().Lookup("sym"))
	viper.BindPFlag("dyld.emu.addr", dyldEmuCmd.Flags().Lookup("addr"))
	viper.BindPFlag("dyld.emu.count", dyldEmuCmd.Flags().Lookup("count"))
	viper.BindPFlag("dyld.emu.state", dyldEmuCmd.Flags().Lookup("state"))
}

// dyldEmuCmd represents the dyld emu command
var dyldEmuCmd = &cobra.Command{
	Use:   "emu <DSC>",
	Short: "🚧 Emulate ARM64 dyld_shared_cache",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// Flags
		symbolName := viper.GetString("dyld.emu.sym")
		startAddr := viper.GetUint64("dyld.emu.addr")
		instructions := viper.GetUint64("dyld.emu.count")
		stateFile := viper.GetString("dyld.emu.state")
		// Validate flags
		if symbolName != "" && startAddr != 0 {
			return fmt.Errorf("cannot specify both --sym and --vaddr")
		}

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		mu, err := emu.NewEmulation(f, &emu.Config{Verbose: viper.GetBool("verbose")})
		if err != nil {
			return err
		}
		defer mu.Close()

		var image *dyld.CacheImage
		if symbolName != "" {
			startAddr, image, err = f.GetSymbolAddress(symbolName)
			if err != nil {
				return err
			}
			fmt.Print(colors.Bold().Sprintf("\n%s:", symbolName))
		} else {
			image, err = f.GetImageContainingVMAddr(startAddr)
			if err != nil {
				return err
			}
		}

		m, err := image.GetMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		/*
		 * Read in data to disassemble
		 */
		if instructions > 0 {
			log.Warnf("emulating %d instructions at %#x", instructions, startAddr)
			uuid, off, err := f.GetOffset(startAddr)
			if err != nil {
				return err
			}
			code, err := f.ReadBytesForUUID(uuid, int64(off), instructions*4)
			if err != nil {
				return err
			}
			if err := mu.SetCode(startAddr, instructions, code); err != nil {
				return fmt.Errorf("failed to set emulation code: %v", err)
			}
		} else {
			if fn, err := m.GetFunctionForVMAddr(startAddr); err == nil {
				uuid, soff, err := f.GetOffset(fn.StartAddr)
				if err != nil {
					return err
				}
				code, err := f.ReadBytesForUUID(uuid, int64(soff), uint64(fn.EndAddr-fn.StartAddr))
				if err != nil {
					return err
				}
				if err := mu.SetCode(fn.StartAddr, fn.EndAddr-fn.StartAddr, code); err != nil {
					return fmt.Errorf("failed to set emulation code: %v", err)
				}
			}
		}

		if err := mu.SetupHooks(); err != nil {
			return fmt.Errorf("failed to setup hooks: %v", err)
		}
		if err := mu.InitStack(); err != nil {
			return fmt.Errorf("failed to setup stack: %v", err)
		}
		// if err := mu.InitHeap(); err != nil {
		// 	return fmt.Errorf("failed to setup heap: %v", err)
		// }

		if len(stateFile) > 0 {
			state, err := emu.ParseState(stateFile)
			if err != nil {
				return fmt.Errorf("failed to parse state file %s: %v", stateFile, err)
			}
			if err := mu.SetState(state); err != nil {
				return fmt.Errorf("failed to set initial state from state file %s: %v", stateFile, err)
			}
		}

		//***********
		//* EMULATE *
		//***********
		if err := mu.Start(); err != nil {
			return err
		}
		log.Info("Emulation Complete ✅")

		return nil
	},
}
