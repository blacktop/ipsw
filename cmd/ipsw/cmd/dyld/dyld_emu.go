//go:build unicorn

/*
Copyright © 2022 blacktop

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
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/emu"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(dyldEmuCmd)

	dyldEmuCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldEmuCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")

	dyldEmuCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// dyldEmuCmd represents the dyld emu command
var dyldEmuCmd = &cobra.Command{
	Use:           "emu",
	Short:         "🚧 Emulate ARM64 dyld_shared_cache",
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	Args:          cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		startAddr, _ := cmd.Flags().GetUint64("vaddr")
		instructions, _ := cmd.Flags().GetUint64("count")

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

		image, err := f.GetImageContainingVMAddr(startAddr)
		if err != nil {
			return err
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
			return fmt.Errorf("failed to setup hooks: %v", err)
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
