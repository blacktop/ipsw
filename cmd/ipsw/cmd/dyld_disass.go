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
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	dyldCmd.AddCommand(dyldDisassCmd)
	// dyldDisassCmd.Flags().Uint64("slide", 0, "dyld_shared_cache slide to remove from --vaddr")
	dyldDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	dyldDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	dyldDisassCmd.Flags().StringP("image", "i", "", "dylib image to search")
	dyldDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	dyldDisassCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	dyldDisassCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	dyldDisassCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	dyldDisassCmd.Flags().Bool("color", false, "Syntax highlight assembly output")
	dyldDisassCmd.Flags().String("input", "", "Input function JSON file")
	dyldDisassCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")

	viper.BindPFlag("dyld.disass.symbol", dyldDisassCmd.Flags().Lookup("symbol"))
	viper.BindPFlag("dyld.disass.vaddr", dyldDisassCmd.Flags().Lookup("vaddr"))
	viper.BindPFlag("dyld.disass.image", dyldDisassCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.disass.count", dyldDisassCmd.Flags().Lookup("count"))
	viper.BindPFlag("dyld.disass.demangle", dyldDisassCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("dyld.disass.json", dyldDisassCmd.Flags().Lookup("json"))
	viper.BindPFlag("dyld.disass.quiet", dyldDisassCmd.Flags().Lookup("quiet"))
	viper.BindPFlag("dyld.disass.color", dyldDisassCmd.Flags().Lookup("color"))
	viper.BindPFlag("dyld.disass.input", dyldDisassCmd.Flags().Lookup("input"))
	viper.BindPFlag("dyld.disass.cache", dyldDisassCmd.Flags().Lookup("cache"))

	dyldDisassCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// disassCmd represents the disass command
var dyldDisassCmd = &cobra.Command{
	Use:           "disass <dyld_shared_cache>",
	Short:         "Disassemble dyld_shared_cache at symbol/vaddr",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var data []byte
		var middleAddr uint64
		var image *dyld.CacheImage

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		symbolName := viper.GetString("dyld.disass.symbol")
		startAddr := viper.GetUint64("dyld.disass.vaddr")
		imageName := viper.GetString("dyld.disass.image")
		instructions := viper.GetUint64("dyld.disass.count")

		demangleFlag := viper.GetBool("dyld.disass.demangle")
		asJSON := viper.GetBool("dyld.disass.json")
		quiet := viper.GetBool("dyld.disass.quiet")
		forceColor := viper.GetBool("dyld.disass.color")

		funcFile := viper.GetString("dyld.disass.input")
		cacheFile := viper.GetString("dyld.disass.cache")

		if forceColor {
			color.NoColor = false
		}

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

		if len(symbolName) > 0 {
			log.Info("Locating symbol: " + symbolName)
			if len(imageName) > 0 {
				startAddr, image, err = f.GetSymbolAddress(symbolName, imageName)
				if err != nil {
					return err
				}
			} else {
				startAddr, image, err = f.GetSymbolAddress(symbolName, "")
				if err != nil {
					return err
				}
			}
			log.Infof("Found symbol in %s", filepath.Base(image.Name))
		} else {
			if len(imageName) > 0 { // ALL funcs in an image
				image, err = f.Image(imageName)
				if err != nil {
					return fmt.Errorf("image not in %s: %v", dscPath, err)
				}

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
						Color:        forceColor,
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
			fdata, _ := ioutil.ReadFile(funcFile)

			var funcs []Func
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
					Color:        forceColor,
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
				Color:        forceColor,
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
