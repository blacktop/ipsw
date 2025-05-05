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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ai"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(DisassCmd)
	// DisassCmd.Flags().Uint64("slide", 0, "dyld_shared_cache slide to remove from --vaddr")
	DisassCmd.Flags().StringSliceP("image", "i", []string{}, "Dylib(s) to disassemble")
	DisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	DisassCmd.Flags().String("symbol-image", "", "Dylib to search for symbol (speeds up symbol lookup)")
	DisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	DisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	DisassCmd.Flags().Bool("dylibs", false, "Analyze all dylibs loaded by the image as well (could improve accuracy)")
	DisassCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	DisassCmd.Flags().BoolP("dec", "D", false, "Decompile assembly")
	DisassCmd.Flags().String("dec-model", "", "LLM model to use for decompilation")
	DisassCmd.Flags().String("dec-lang", "", "Language to decompile to (C, ObjC or Swift)")
	DisassCmd.Flags().Float64("dec-temp", 0.2, "LLM temperature for decompilation")
	DisassCmd.Flags().Float64("dec-top-p", 0.1, "LLM top_p for decompilation")
	DisassCmd.Flags().String("llm", "", "LLM provider to use for decompilation (ollama, copilot, etc.)")
	DisassCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	DisassCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	DisassCmd.Flags().Bool("force", false, "Continue to disassemble even if there are analysis errors")
	DisassCmd.Flags().String("input", "", "Input function JSON file")
	DisassCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	DisassCmd.MarkFlagsMutuallyExclusive("symbol", "vaddr", "input", "image")
	// DisassCmd.Flags().Bool("replace", false, "Replace .a2s")
	viper.BindPFlag("dyld.disass.image", DisassCmd.Flags().Lookup("image"))
	viper.BindPFlag("dyld.disass.symbol", DisassCmd.Flags().Lookup("symbol"))
	viper.BindPFlag("dyld.disass.symbol-image", DisassCmd.Flags().Lookup("symbol-image"))
	viper.BindPFlag("dyld.disass.vaddr", DisassCmd.Flags().Lookup("vaddr"))
	viper.BindPFlag("dyld.disass.count", DisassCmd.Flags().Lookup("count"))
	viper.BindPFlag("dyld.disass.dylibs", DisassCmd.Flags().Lookup("dylibs"))
	viper.BindPFlag("dyld.disass.demangle", DisassCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("dyld.disass.dec", DisassCmd.Flags().Lookup("dec"))
	viper.BindPFlag("dyld.disass.dec-model", DisassCmd.Flags().Lookup("dec-model"))
	viper.BindPFlag("dyld.disass.dec-lang", DisassCmd.Flags().Lookup("dec-lang"))
	viper.BindPFlag("dyld.disass.dec-temp", DisassCmd.Flags().Lookup("dec-temp"))
	viper.BindPFlag("dyld.disass.dec-top-p", DisassCmd.Flags().Lookup("dec-top-p"))
	viper.BindPFlag("dyld.disass.llm", DisassCmd.Flags().Lookup("llm"))
	viper.BindPFlag("dyld.disass.json", DisassCmd.Flags().Lookup("json"))
	viper.BindPFlag("dyld.disass.quiet", DisassCmd.Flags().Lookup("quiet"))
	viper.BindPFlag("dyld.disass.force", DisassCmd.Flags().Lookup("force"))
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
	Example: heredoc.Doc(`
		# Disassemble all images in dyld_shared_cache
		❯ ipsw dsc disass DSC
		# Disassemble a few dylibs in dyld_shared_cache (NOTE: multiple -i flags OR comma separated dylibs)
		❯ ipsw dsc disass DSC --image libsystem_kernel.dylib --image libsystem_platform.dylib,libsystem_pthread.dylib
		# Disassemble a symbol in dyld_shared_cache (NOTE: supply --symbol-image 'libsystem_malloc.dylib' for faster lookup)
		❯ ipsw dsc disass DSC --symbol _malloc
		# Disassemble a function at a virtual address in dyld_shared_cache
		❯ ipsw dsc disass DSC --vaddr 0x1b19d6940
		# Disassemble a function at a virtual address in dyld_shared_cache and output as JSON
		❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --json
		# Disassemble a function at a virtual address in dyld_shared_cache and demangle symbol names
		❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --demangle
		# Disassemble a function at a virtual address in dyld_shared_cache and do NOT markup analysis (Faster)
		❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --quiet
		# Decompile a function at a virtual address in dyld_shared_cache (via GitHub Copilot)
		❯ ipsw dsc disass DSC --vaddr 0x1b19d6940 --dec --dec-model "Claude 3.7 Sonnet"`),
	Args: cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var data []byte
		var middleAddr uint64
		var image *dyld.CacheImage
		var images []*dyld.CacheImage

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		imageNames := viper.GetStringSlice("dyld.disass.image")
		symbolName := viper.GetString("dyld.disass.symbol")
		symbolImageName := viper.GetString("dyld.disass.symbol-image")
		startAddr := viper.GetUint64("dyld.disass.vaddr")
		instructions := viper.GetUint64("dyld.disass.count")

		decompile := viper.GetBool("dyld.disass.dec")
		demangleFlag := viper.GetBool("dyld.disass.demangle")
		asJSON := viper.GetBool("dyld.disass.json")
		quiet := viper.GetBool("dyld.disass.quiet")

		funcFile := viper.GetString("dyld.disass.input")
		cacheFile := viper.GetString("dyld.disass.cache")
		// validate flags
		if len(symbolImageName) > 0 && len(symbolName) == 0 {
			return fmt.Errorf("you must also supply a --symbol with --symbol-image flag")
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

		if len(symbolName) == 0 && startAddr == 0 && len(funcFile) == 0 { /* DEFAULT: disassemble image(s) */

			if len(imageNames) == 0 {
				images = f.Images // disassemble ALL images
			} else {
				for _, name := range imageNames {
					image, err := f.Image(name)
					if err != nil {
						return fmt.Errorf("failed to find image %s: %v", name, err)
					}
					images = append(images, image)
				}
			}

			for _, image := range images {
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
							if !viper.GetBool("dyld.disass.force") {
								return fmt.Errorf("failed to analyze image %s: %v (use --force to continue anyway)", filepath.Base(image.Name), err)
							}
						}
						if err := engine.Triage(); err != nil {
							return fmt.Errorf("first pass triage failed: %v", err)
						}
						if viper.GetBool("dyld.disass.dylibs") {
							for _, img := range engine.Dylibs() {
								if err := img.Analyze(); err != nil {
									if !viper.GetBool("dyld.disass.force") {
										return fmt.Errorf("failed to analyze image %s: %v (use --force to continue anyway)", filepath.Base(img.Name), err)
									}
								}
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
					asm := disass.Disassemble(engine)
					if decompile {
						promptFmt, lexer, err := disass.GetPrompt(asm, viper.GetString("dyld.disass.dec-lang"))
						if err != nil {
							return fmt.Errorf("failed to get prompt format string and syntax highlight lexer: %v", err)
						}
						llm, err := ai.NewAI(context.Background(), &ai.Config{
							Provider:    viper.GetString("dyld.disass.llm"),
							Prompt:      fmt.Sprintf(promptFmt, asm),
							Model:       viper.GetString("dyld.disass.dec-model"),
							Temperature: viper.GetFloat64("dyld.disass.dec-temp"),
							TopP:        viper.GetFloat64("dyld.disass.dec-top-p"),
							Stream:      true,
						})
						if err != nil {
							return fmt.Errorf("failed to create llm client: %v", err)
						}
						if !viper.IsSet("dyld.disass.dec-model") {
							var choice string
							prompt := &survey.Select{
								Message:  "Select model to use:",
								Options:  llm.Models(),
								PageSize: 10,
							}
							if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
								log.Warn("Exiting...")
								return nil
							}
							if err := llm.SetModel(choice); err != nil {
								return fmt.Errorf("failed to set llm model: %v", err)
							}
						}
						s := spinner.New(spinner.CharSets[38], 100*time.Millisecond)
						s.Prefix = color.BlueString("   • Decompiling... ")
						s.Start()

						decmp, err := llm.Chat()
						s.Stop()
						if err != nil {
							return fmt.Errorf("failed to decompile via llm: %v", err)
						}
						if viper.GetBool("color") && !viper.GetBool("no-color") {
							if err := quick.Highlight(os.Stdout, "\n"+string(decmp)+"\n", lexer, "terminal256", "nord"); err != nil {
								return err
							}
						} else {
							fmt.Println(string(decmp))
						}
					} else {
						fmt.Println(asm)
					}
				}
			}

		} else { /* disassemble symbol, vaddr or input func file */

			if len(symbolName) > 0 {
				// Calculate start address from symbol
				log.Info("Locating symbol: " + symbolName)
				if len(symbolImageName) > 0 {
					image, err = f.Image(symbolImageName)
					if err != nil {
						return fmt.Errorf("failed to find image %s: %v", symbolImageName, err)
					}
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
					log.Infof("Found symbol in %s", filepath.Base(image.Name))
				}
			}

			if len(funcFile) > 0 { // INPUT FUNC FILE
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
							if !viper.GetBool("dyld.disass.force") {
								return fmt.Errorf("failed to analyze image %s: %v (use --force to continue anyway)", filepath.Base(image.Name), err)
							}
						}
						if err := engine.Triage(); err != nil {
							return fmt.Errorf("first pass triage failed: %v", err)
						}
						if viper.GetBool("dyld.disass.dylibs") {
							for _, img := range engine.Dylibs() {
								if err := img.Analyze(); err != nil {
									if !viper.GetBool("dyld.disass.force") {
										return fmt.Errorf("failed to analyze image %s: %v (use --force to continue anyway)", filepath.Base(img.Name), err)
									}
								}
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
					asm := disass.Disassemble(engine)
					if decompile {
						promptFmt, lexer, err := disass.GetPrompt(asm, viper.GetString("dyld.disass.dec-lang"))
						if err != nil {
							return fmt.Errorf("failed to get prompt format string and syntax highlight lexer: %v", err)
						}
						llm, err := ai.NewAI(context.Background(), &ai.Config{
							Provider:    viper.GetString("dyld.disass.llm"),
							Prompt:      fmt.Sprintf(promptFmt, asm),
							Model:       viper.GetString("dyld.disass.dec-model"),
							Temperature: viper.GetFloat64("dyld.disass.dec-temp"),
							TopP:        viper.GetFloat64("dyld.disass.dec-top-p"),
							Stream:      true,
						})
						if err != nil {
							return fmt.Errorf("failed to create llm client: %v", err)
						}
						if !viper.IsSet("dyld.disass.dec-model") {
							var choice string
							prompt := &survey.Select{
								Message:  "Select model to use:",
								Options:  llm.Models(),
								PageSize: 10,
							}
							if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
								log.Warn("Exiting...")
								return nil
							}
							if err := llm.SetModel(choice); err != nil {
								return fmt.Errorf("failed to set llm model: %v", err)
							}
						}
						s := spinner.New(spinner.CharSets[38], 100*time.Millisecond)
						s.Prefix = color.BlueString("   • Decompiling... ")
						s.Start()

						decmp, err := llm.Chat()
						s.Stop()
						if err != nil {
							return fmt.Errorf("failed to decompile via llm: %v", err)
						}
						if viper.GetBool("color") && !viper.GetBool("no-color") {
							if err := quick.Highlight(os.Stdout, "\n"+string(decmp)+"\n", lexer, "terminal256", "nord"); err != nil {
								return err
							}
						} else {
							fmt.Println(string(decmp))
						}
					} else {
						fmt.Println(asm)
					}
				}
			} else { // SYMBOL or VAADDR
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
					if image, err = f.GetImageContainingVMAddr(startAddr); err == nil {
						if !quiet {
							if err := image.Analyze(); err != nil {
								if !viper.GetBool("dyld.disass.force") {
									return fmt.Errorf("failed to analyze image %s: %v (use --force to continue anyway)", filepath.Base(image.Name), err)
								}
							}
						}
						m, err := image.GetMacho()
						if err != nil {
							return err
						}
						defer m.Close()
						fn, err := m.GetFunctionForVMAddr(startAddr)
						if err != nil {
							return fmt.Errorf("failed to find function for 0x%x: %v", startAddr, err)
						}
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
					} else { // vmaddr not in image; fallback to reading instructions but set count to 100
						log.WithError(err).Warn("failed to find image containing vmaddr; falling back to reading raw instructions")
						if instructions == 0 {
							log.Warn("setting instruction count to 100, to change use --count flag")
							instructions = 100
						}
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
						return fmt.Errorf("first pass triage failed: %v (use --force to continue anyway)", err)
					}
					if viper.GetBool("dyld.disass.dylibs") {
						for _, img := range engine.Dylibs() {
							if err := img.Analyze(); err != nil {
								if !viper.GetBool("dyld.disass.force") {
									return fmt.Errorf("failed to analyze image %s: %v (use --force to continue anyway)", filepath.Base(img.Name), err)
								}
							}
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
				asm := disass.Disassemble(engine)
				if decompile {
					promptFmt, lexer, err := disass.GetPrompt(asm, viper.GetString("dyld.disass.dec-lang"))
					if err != nil {
						return fmt.Errorf("failed to get prompt format string and syntax highlight lexer: %v", err)
					}
					llm, err := ai.NewAI(context.Background(), &ai.Config{
						Provider:    viper.GetString("dyld.disass.llm"),
						Prompt:      fmt.Sprintf(promptFmt, asm),
						Model:       viper.GetString("dyld.disass.dec-model"),
						Temperature: viper.GetFloat64("dyld.disass.dec-temp"),
						TopP:        viper.GetFloat64("dyld.disass.dec-top-p"),
						Stream:      true,
					})
					if err != nil {
						return fmt.Errorf("failed to create llm client: %v", err)
					}
					if !viper.IsSet("dyld.disass.dec-model") {
						var choice string
						prompt := &survey.Select{
							Message:  "Select model to use:",
							Options:  llm.Models(),
							PageSize: 10,
						}
						if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
							log.Warn("Exiting...")
							return nil
						}
						if err := llm.SetModel(choice); err != nil {
							return fmt.Errorf("failed to set llm model: %v", err)
						}
					}
					s := spinner.New(spinner.CharSets[38], 100*time.Millisecond)
					s.Prefix = color.BlueString("   • Decompiling... ")
					s.Start()

					decmp, err := llm.Chat()
					s.Stop()
					if err != nil {
						return fmt.Errorf("failed to decompile via llm: %v", err)
					}
					if viper.GetBool("color") && !viper.GetBool("no-color") {
						if err := quick.Highlight(os.Stdout, "\n"+string(decmp)+"\n", lexer, "terminal256", "nord"); err != nil {
							return err
						}
					} else {
						fmt.Println(string(decmp))
					}
				} else {
					fmt.Println(asm)
				}
			}
		}

		return nil
	},
}
