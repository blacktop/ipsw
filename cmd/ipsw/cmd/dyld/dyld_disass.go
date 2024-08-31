/*
Copyright © 2018-2024 blacktop

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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(DisassCmd)
	// DisassCmd.Flags().Uint64("slide", 0, "dyld_shared_cache slide to remove from --vaddr")
	DisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	DisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	DisassCmd.Flags().StringP("image", "i", "", "dylib image to search")
	DisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	DisassCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	DisassCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	DisassCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	DisassCmd.Flags().String("input", "", "Input function JSON file")
	DisassCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	// DisassCmd.Flags().Bool("replace", false, "Replace .a2s")

	viper.BindPFlag("dyld.disass.symbol", DisassCmd.Flags().Lookup("symbol"))
	viper.BindPFlag("dyld.disass.vaddr", DisassCmd.Flags().Lookup("vaddr"))
	viper.BindPFlag("dyld.disass.image", DisassCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.disass.count", DisassCmd.Flags().Lookup("count"))
	viper.BindPFlag("dyld.disass.demangle", DisassCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("dyld.disass.json", DisassCmd.Flags().Lookup("json"))
	viper.BindPFlag("dyld.disass.quiet", DisassCmd.Flags().Lookup("quiet"))
	viper.BindPFlag("dyld.disass.color", DisassCmd.Flags().Lookup("color"))
	viper.BindPFlag("dyld.disass.input", DisassCmd.Flags().Lookup("input"))
	viper.BindPFlag("dyld.disass.cache", DisassCmd.Flags().Lookup("cache"))
	// viper.BindPFlag("dyld.disass.replace", DisassCmd.Flags().Lookup("replace"))
}

// DisassCmd represents the disass command
var DisassCmd = &cobra.Command{
	Use:     "disass <DSC>",
	Aliases: []string{"dis"},
	Short:   "Disassemble at symbol/vaddr",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var data []byte
		var middleAddr uint64
		var image *dyld.CacheImage

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		symbolName := viper.GetString("dyld.disass.symbol")
		startAddr := viper.GetUint64("dyld.disass.vaddr")
		imageName := viper.GetString("dyld.disass.image")
		instructions := viper.GetUint64("dyld.disass.count")

		demangleFlag := viper.GetBool("dyld.disass.demangle")
		asJSON := viper.GetBool("dyld.disass.json")
		quiet := viper.GetBool("dyld.disass.quiet")

		funcFile := viper.GetString("dyld.disass.input")
		cacheFile := viper.GetString("dyld.disass.cache")

		if len(symbolName) > 0 && startAddr != 0 {
			return fmt.Errorf("you can only use --symbol OR --vaddr (not both)")
		} else if len(funcFile) > 0 && (len(symbolName) > 0 || startAddr != 0 || len(imageName) > 0) {
			return fmt.Errorf("you can NOT combine the --input flag with other filter flags (--symbol|--vaddr|--image)")
		} else if len(symbolName) == 0 && startAddr == 0 {
			if len(imageName) == 0 && len(funcFile) == 0 {
				return fmt.Errorf("if you don't supply a --image or --input flag you MUST supply a --symbol OR --vaddr to disassemble")
			}
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

		if !quiet || len(symbolName) > 0 {
			if len(cacheFile) == 0 {
				cacheFile = dscPath + ".a2s"
			}
			if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
				return err
			}
		}

		if len(imageName) > 0 {
			image, err = f.Image(imageName)
			if err != nil {
				return err
			}
		}

		if len(symbolName) > 0 {
			log.Info("Locating symbol: " + symbolName)
			if len(imageName) > 0 {
				sym, err := image.GetSymbol(symbolName)
				if err != nil {
					return err
				}
				startAddr = sym.Address
			} else {
				startAddr, image, err = f.GetSymbolAddress(symbolName)
				if err != nil {
					return err
				}
			}
			log.Infof("Found symbol in %s", filepath.Base(image.Name))
		} else {
			if len(imageName) > 0 { // ALL funcs in an image
				m, err := image.GetMacho()
				if err != nil {
					return err
				}
				defer m.Close()

				for idx, fn := range m.GetFunctions() {
					data, err := m.GetFunctionData(fn)
					if err != nil {
						log.Errorf("failed to get data for function: %v", err)
						continue
					}

					engine := dyld.NewDyldDisass(f, &disass.Config{
						Image:        image.Name,
						Data:         data,
						StartAddress: fn.StartAddr,
						Middle:       0,
						AsJSON:       asJSON,
						Demangle:     demangleFlag,
						Quite:        quiet,
						Color:        viper.GetBool("color") && !viper.GetBool("no-color"),
					})

					if !quiet {
						//***********************
						//* First pass ANALYSIS *
						//***********************
						if err := image.Analyze(); err != nil {
							return err
						}
						if err := engine.Triage(); err != nil {
							return fmt.Errorf("first pass triage failed: %v", err)
						}
						for _, img := range engine.Dylibs() {
							if err := img.Analyze(); err != nil {
								return err
							}
						}
					} else {
						if !asJSON {
							if idx == 0 {
								fmt.Printf("sub_%x:\n", fn.StartAddr)
							} else {
								fmt.Printf("\nsub_%x:\n", fn.StartAddr)
							}
						}
					}

					//***************
					//* DISASSEMBLE *
					//***************
					disass.Disassemble(engine)
				}

				return nil
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

		if len(funcFile) > 0 {
			funcFile = filepath.Clean(funcFile)
			fdata, _ := os.ReadFile(funcFile)

			var funcs []dscFunc
			if err := json.Unmarshal(fdata, &funcs); err != nil {
				return fmt.Errorf("failed to parse function JSON file %s: %v", funcFile, err)
			}

			for _, fn := range funcs {
				uuid, off, err := f.GetOffset(fn.Start)
				if err != nil {
					return err
				}

				data, err := f.ReadBytesForUUID(uuid, int64(off), fn.Size)
				if err != nil {
					return err
				}

				engine := dyld.NewDyldDisass(f, &disass.Config{
					Image:        fn.Image,
					Data:         data,
					StartAddress: fn.Start,
					Middle:       0,
					AsJSON:       asJSON,
					Demangle:     demangleFlag,
					Quite:        quiet,
					Color:        viper.GetBool("color") && !viper.GetBool("no-color"),
				})

				if !quiet {
					//***********************
					//* First pass ANALYSIS *
					//***********************
					image, err = f.Image(fn.Image)
					if err != nil {
						return err
					}
					if err := image.Analyze(); err != nil {
						return err
					}
					if err := engine.Triage(); err != nil {
						return fmt.Errorf("first pass triage failed: %v", err)
					}
					for _, img := range engine.Dylibs() {
						if err := img.Analyze(); err != nil {
							return err
						}
					}
				} else {
					if !asJSON {
						if len(fn.Name) > 0 {
							fmt.Printf("\n%s:\n", fn.Name)
						} else {
							fmt.Printf("\nsub_%x:\n", fn.Start)
						}
					}
				}

				//***************
				//* DISASSEMBLE *
				//***************
				disass.Disassemble(engine)
			}
		} else {
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
				image, err = f.GetImageContainingVMAddr(startAddr)
				if err != nil {
					return err
				}
				if err := image.Analyze(); err != nil {
					return err
				}
				m, err := image.GetMacho()
				if err != nil {
					return err
				}
				defer m.Close()
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
						middleAddr = startAddr
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

			// // Apply slide
			// if slide > 0 {
			// 	startAddr = startAddr - slide
			// }
			var imageName string
			if image != nil {
				imageName = image.Name
			}
			engine := dyld.NewDyldDisass(f, &disass.Config{
				Image:        imageName,
				Data:         data,
				StartAddress: startAddr,
				Middle:       middleAddr,
				AsJSON:       asJSON,
				Demangle:     demangleFlag,
				Quite:        quiet,
				Color:        viper.GetBool("color") && !viper.GetBool("no-color"),
			})

			if !quiet {
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
			} else {
				if !asJSON {
					if len(symbolName) > 0 {
						fmt.Printf("%s:\n", symbolName)
					} else {
						fmt.Printf("sub_%x:\n", startAddr)
					}
				}
			}

			//***************
			//* DISASSEMBLE *
			//***************
			disass.Disassemble(engine)
		}

		return nil
	},
}
