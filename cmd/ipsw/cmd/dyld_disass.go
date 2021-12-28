/*
Copyright © 2021 blacktop

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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(dyldDisassCmd)

	dyldDisassCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	dyldDisassCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	dyldDisassCmd.Flags().Uint64("slide", 0, "dyld_shared_cache slide to remove from --vaddr")
	dyldDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	dyldDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	dyldDisassCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	dyldDisassCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	dyldDisassCmd.Flags().StringP("image", "i", "", "dylib image to search")

	symaddrCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// disassCmd represents the disass command
var dyldDisassCmd = &cobra.Command{
	Use:           "disass <dyld_shared_cache>",
	Short:         "Disassemble dyld_shared_cache symbol/vaddr in an image",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var data []byte
		var isMiddle bool
		var image *dyld.CacheImage

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		imageName, _ := cmd.Flags().GetString("image")
		instructions, _ := cmd.Flags().GetUint64("count")
		startAddr, _ := cmd.Flags().GetUint64("vaddr")
		symbolName, _ := cmd.Flags().GetString("symbol")
		cacheFile, _ := cmd.Flags().GetString("cache")
		slide, _ := cmd.Flags().GetUint64("slide")
		asJSON, _ := cmd.Flags().GetBool("json")
		demangleFlag, _ := cmd.Flags().GetBool("demangle")
		quiet, _ := cmd.Flags().GetBool("quiet")

		if len(symbolName) > 0 && startAddr != 0 {
			return fmt.Errorf("you can only use --symbol OR --vaddr (not both)")
		} else if len(symbolName) == 0 && startAddr == 0 {
			return fmt.Errorf("you must supply a --symbol OR --vaddr to disassemble")
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

		if !f.IsArm64() {
			log.Errorf("can only disassemble arm64 caches")
			return nil
		}

		if len(symbolName) > 0 {
			if len(imageName) == 0 {
				if len(cacheFile) == 0 {
					cacheFile = dscPath + ".a2s"
				}
				if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
					return err
				}
			} else {
				image, err = f.Image(imageName)
				if err != nil {
					return fmt.Errorf("image not in %s: %v", dscPath, err)
				}
				utils.Indent(log.Warn, 2)("parsing public symbols...")
				if err := f.GetAllExportedSymbolsForImage(image, false); err != nil {
					log.Error("failed to parse exported symbols")
				}
				utils.Indent(log.Warn, 2)("parsing private symbols...")
				if err := f.GetLocalSymbolsForImage(image); err != nil {
					if errors.Is(err, dyld.ErrNoLocals) {
						utils.Indent(log.Warn, 2)(err.Error())
					} else if err != nil {
						return err
					}
				}
			}

			log.Info("Locating symbol: " + symbolName)
			startAddr, image, err = f.GetSymbolAddress(symbolName, imageName)
			if err != nil {
				return err
			}

		} else { // startAddr > 0
			if slide > 0 {
				startAddr = startAddr - slide
			}
		}

		if image == nil {
			image, err = f.GetImageContainingTextAddr(startAddr)
			if err != nil {
				return err
			}
		}

		log.WithFields(log.Fields{"dylib": image.Name}).Info("Found symbol")

		m, err := image.GetMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		/*
		 * Load symbols from the target sym/addr's image
		 */
		if len(symbolName) == 0 {
			utils.Indent(log.Warn, 2)("parsing public symbols...")
			if err := f.GetAllExportedSymbolsForImage(image, false); err != nil {
				log.Error("failed to parse exported symbols")
			}
			utils.Indent(log.Warn, 2)("parsing private symbols...")
			if err := f.GetLocalSymbolsForImage(image); err != nil {
				if errors.Is(err, dyld.ErrNoLocals) {
					utils.Indent(log.Warn, 2)(err.Error())
				} else if err != nil {
					return err
				}
			}
		}

		/*
		 * Load symbols from all of the dylibs loaded by the target sym/addr's image
		 */
		// if len(symbolName) == 0 {
		// 	if !image.Analysis.State.IsDepsDone() {
		// 		utils.Indent(log.Warn, 2)("parsing imported dylib symbols...")
		// 		if err := f.ImageDependencies(image.Name); err == nil {
		// 			for _, dep := range image.Analysis.Dependencies {
		// 				if err := f.GetAllExportedSymbolsForImage(dep, false); err != nil {
		// 					log.Errorf("failed to parse exported symbols for %s", dep)
		// 				}
		// 				if err := f.GetLocalSymbolsForImage(dep); err != nil {
		// 					log.Errorf("failed to parse local symbols for %s", dep)
		// 				}
		// 				dM, err := f.Image(dep).GetMacho()
		// 				if err != nil {
		// 					return err
		// 				}
		// 				// TODO: create a dep tree and analyze them all (lazily if possible)
		// 				fmt.Println(dep)
		// 				if err := f.ParseSymbolStubs(dM); err != nil {
		// 					return err
		// 				}
		// 				dM.Close()
		// 			}
		// 		}
		// 		image.Analysis.State.SetDeps(true)
		// 	}
		// }

		if m.HasObjC() {
			log.Info("Parsing ObjC runtime structures...")
			if err := f.ParseObjcForImage(image.Name); err != nil {
				return fmt.Errorf("failed to parse objc data for image %s: %v", image.Name, err)
			}
		}

		if err := image.Analyze(); err != nil {
			return err
		}

		/*
		 * Read in data to disassemble
		 */
		if instructions > 0 {
			uuid, off, err := f.GetOffset(startAddr)
			if err != nil {
				return err
			}
			data, err = f.ReadBytesForUUID(uuid, int64(off), instructions*4)
			if err != nil {
				return err
			}
		} else {
			if fn, err := m.GetFunctionForVMAddr(startAddr); err == nil {
				uuid, soff, err := f.GetOffset(fn.StartAddr)
				if err != nil {
					return err
				}
				data, err = f.ReadBytesForUUID(uuid, int64(soff), uint64(fn.EndAddr-fn.StartAddr))
				if err != nil {
					return err
				}
				if startAddr != fn.StartAddr {
					isMiddle = true
					startAddr = fn.StartAddr
				}
			} else {
				log.Warnf("disassembling 100 instructions at %#x", startAddr)
				instructions = 100
				uuid, off, err := f.GetOffset(startAddr)
				if err != nil {
					return err
				}
				data, err = f.ReadBytesForUUID(uuid, int64(off), instructions*4)
				if err != nil {
					return err
				}
			}
		}
		if data == nil {
			log.Fatal("failed to disassemble")
		}

		engine := dyld.NewDyldDisass(f, &disass.Config{
			Image:        image.Name,
			Data:         data,
			StartAddress: startAddr,
			Middle:       isMiddle,
			AsJSON:       asJSON,
			Demangle:     demangleFlag,
			Quite:        quiet,
		})

		//***********************
		//* First pass ANALYSIS *
		//***********************
		if err := engine.Triage(); err != nil {
			return fmt.Errorf("first pass triage failed: %v", err)
		}
		for _, img := range engine.Dylibs() {
			if err := img.Analyze(); err != nil {
				return err
			}
		}

		//***************
		//* DISASSEMBLE *
		//***************
		disass.Disassemble(engine)

		return nil
	},
}
