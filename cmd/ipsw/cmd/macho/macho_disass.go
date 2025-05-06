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
package macho

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/ai"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/briandowns/spinner"
	"github.com/caarlos0/ctrlc"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoDisassCmd)
	// machoDisassCmd.Flags().Uint64("slide", 0, "MachO slide to remove from --vaddr")
	machoDisassCmd.Flags().String("arch", "", "Which architecture to use for fat/universal MachO")
	machoDisassCmd.Flags().BoolP("entry", "e", false, "Disassemble entry point")
	machoDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	machoDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	machoDisassCmd.Flags().Uint64P("off", "o", 0, "File offset to start disassembling")
	machoDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	machoDisassCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	machoDisassCmd.Flags().BoolP("dec", "D", false, "Decompile assembly")
	machoDisassCmd.Flags().String("dec-model", "", "LLM model to use for decompilation")
	machoDisassCmd.Flags().String("dec-lang", "", "Language to decompile to (C, ObjC or Swift)")
	machoDisassCmd.Flags().Float64("dec-temp", 0.2, "LLM temperature for decompilation")
	machoDisassCmd.Flags().Float64("dec-top-p", 0.1, "LLM top_p for decompilation")
	machoDisassCmd.Flags().String("llm", "", "LLM provider to use for decompilation (ollama, copilot, etc.)")
	machoDisassCmd.RegisterFlagCompletionFunc("llm", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return ai.Providers, cobra.ShellCompDirectiveDefault
	})
	machoDisassCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	machoDisassCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	machoDisassCmd.Flags().Bool("force", false, "Continue to disassemble even if there are analysis errors")
	// machoDisassCmd.Flags().StringP("input", "i", "", "Input function JSON file")
	machoDisassCmd.Flags().StringP("fileset-entry", "t", "", "Which fileset entry to analyze")
	machoDisassCmd.Flags().BoolP("all-fileset-entries", "z", false, "Parse all fileset entries")
	machoDisassCmd.Flags().StringP("section", "x", "", "Disassemble an entire segment/section (i.e. __TEXT_EXEC.__text)")
	machoDisassCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")
	machoDisassCmd.Flags().Bool("replace", false, "Replace .a2s")
	machoDisassCmd.MarkFlagsMutuallyExclusive("entry", "symbol", "vaddr", "off")

	viper.BindPFlag("macho.disass.arch", machoDisassCmd.Flags().Lookup("arch"))
	viper.BindPFlag("macho.disass.entry", machoDisassCmd.Flags().Lookup("entry"))
	viper.BindPFlag("macho.disass.symbol", machoDisassCmd.Flags().Lookup("symbol"))
	viper.BindPFlag("macho.disass.vaddr", machoDisassCmd.Flags().Lookup("vaddr"))
	viper.BindPFlag("macho.disass.off", machoDisassCmd.Flags().Lookup("off"))
	viper.BindPFlag("macho.disass.count", machoDisassCmd.Flags().Lookup("count"))
	viper.BindPFlag("macho.disass.demangle", machoDisassCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("macho.disass.dec", machoDisassCmd.Flags().Lookup("dec"))
	viper.BindPFlag("macho.disass.dec-model", machoDisassCmd.Flags().Lookup("dec-model"))
	viper.BindPFlag("macho.disass.dec-lang", machoDisassCmd.Flags().Lookup("dec-lang"))
	viper.BindPFlag("macho.disass.dec-temp", machoDisassCmd.Flags().Lookup("dec-temp"))
	viper.BindPFlag("macho.disass.dec-top-p", machoDisassCmd.Flags().Lookup("dec-top-p"))
	viper.BindPFlag("macho.disass.llm", machoDisassCmd.Flags().Lookup("llm"))
	viper.BindPFlag("macho.disass.json", machoDisassCmd.Flags().Lookup("json"))
	viper.BindPFlag("macho.disass.quiet", machoDisassCmd.Flags().Lookup("quiet"))
	viper.BindPFlag("macho.disass.force", machoDisassCmd.Flags().Lookup("force"))
	// viper.BindPFlag("macho.disass.input", machoDisassCmd.Flags().Lookup("input"))
	viper.BindPFlag("macho.disass.fileset-entry", machoDisassCmd.Flags().Lookup("fileset-entry"))
	viper.BindPFlag("macho.disass.all-fileset-entries", machoDisassCmd.Flags().Lookup("all-fileset-entries"))
	viper.BindPFlag("macho.disass.section", machoDisassCmd.Flags().Lookup("section"))
	viper.BindPFlag("macho.disass.cache", machoDisassCmd.Flags().Lookup("cache"))
	viper.BindPFlag("macho.disass.replace", machoDisassCmd.Flags().Lookup("replace"))

	machoDisassCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoDisassCmd represents the dis command
var machoDisassCmd = &cobra.Command{
	Use:           "disass <MACHO>",
	Short:         "Disassemble ARM64 MachO at symbol/vaddr",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		var ms []*macho.File
		var middleAddr uint64
		var engine *disass.MachoDisass

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		selectedArch := viper.GetString("macho.info.arch")
		entryStart := viper.GetBool("macho.disass.entry")
		symbolName := viper.GetString("macho.disass.symbol")
		startAddr := viper.GetUint64("macho.disass.vaddr")
		startOff := viper.GetUint64("macho.disass.off")
		instructions := viper.GetUint64("macho.disass.count")
		segmentSection := viper.GetString("macho.disass.section")

		decompile := viper.GetBool("macho.disass.dec")
		demangleFlag := viper.GetBool("macho.disass.demangle")
		asJSON := viper.GetBool("macho.disass.json")
		quiet := viper.GetBool("macho.disass.quiet")

		// funcFile := viper.GetString("macho.disass.input")
		filesetEntry := viper.GetString("macho.disass.fileset-entry")
		cacheFile := viper.GetString("macho.disass.cache")

		allFuncs := false

		// validate args
		if len(symbolName) == 0 && startAddr == 0 && startOff == 0 && !entryStart {
			allFuncs = true
			// return fmt.Errorf("you must supply a --symbol OR --vaddr to disassemble")
		}
		if len(filesetEntry) > 0 && viper.GetBool("macho.disass.all-fileset-entries") {
			return fmt.Errorf("you can only use --fileset-entry OR --all-fileset-entries (not both)")
		} else if viper.GetBool("macho.disass.all-fileset-entries") && len(segmentSection) == 0 {
			log.Warn("you probably want to add --section '__TEXT_EXEC.__text'; as the NEW MH_FILESET entries don't ALL have LC_FUNCTION_STARTS (iOS18 added LC_FUNCTION_STARTS to all KEXTs ❤️)")
		}
		if viper.IsSet("macho.disass.llm") {
			if !slices.Contains(ai.Providers, viper.GetString("macho.disass.llm")) {
				return fmt.Errorf("invalid LLM provider '%s', must be one of: %s", viper.GetString("macho.disass.llm"), strings.Join(ai.Providers, ", "))
			}
		}

		machoPath := filepath.Clean(args[0])

		if ok, err := magic.IsMachO(machoPath); !ok {
			return fmt.Errorf("failed to detect file type: %v", err)
		}

		fat, err := macho.OpenFat(machoPath)
		if err != nil && err != macho.ErrNotFat {
			log.Fatal(err.Error())
		}
		if err == macho.ErrNotFat {
			m, err = macho.Open(machoPath)
			if err != nil {
				log.Fatal(err.Error())
			}
		} else {
			var options []string
			var shortOptions []string
			for _, arch := range fat.Arches {
				if strings.Contains(strings.ToLower(arch.SubCPU.String(arch.CPU)), "arm64") {
					options = append(options, fmt.Sprintf("%s, %s", arch.CPU, arch.SubCPU.String(arch.CPU)))
					shortOptions = append(shortOptions, strings.ToLower(arch.SubCPU.String(arch.CPU)))
					m = arch.File //
				}
			}

			if len(shortOptions) > 1 {
				if len(selectedArch) > 0 {
					found := false
					for i, opt := range shortOptions {
						if strings.Contains(strings.ToLower(opt), strings.ToLower(selectedArch)) {
							m = fat.Arches[i].File
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("--arch '%s' not found in: %s", selectedArch, strings.Join(shortOptions, ", "))
					}
				} else {
					choice := 0
					prompt := &survey.Select{
						Message: "Detected a universal MachO file, please select an architecture to analyze:",
						Options: options,
					}
					survey.AskOne(prompt, &choice)
					m = fat.Arches[choice].File
				}
			}
		}

		if !strings.Contains(strings.ToLower(m.FileHeader.SubCPU.String(m.CPU)), "arm64") {
			return fmt.Errorf("can only disassemble arm64 binaries")
		}

		if m.FileTOC.FileHeader.Type == types.MH_FILESET &&
			len(filesetEntry) == 0 && !viper.GetBool("macho.disass.all-fileset-entries") {
			return fmt.Errorf("file is a MH_FILESET, you must supply a --fileset-entry OR --all-fileset-entries")
		}

		if len(filesetEntry) > 0 {
			if m.FileTOC.FileHeader.Type == types.MH_FILESET {
				m, err = m.GetFileSetFileByName(filesetEntry)
				if err != nil {
					return fmt.Errorf("failed to parse entry %s: %v", filesetEntry, err)
				}
			} else {
				log.Error("MachO type is not MH_FILESET (cannot use --fileset-entry)")
			}
			ms = append(ms, m)
		} else if viper.GetBool("macho.disass.all-fileset-entries") {
			for _, fe := range m.FileSets() {
				mfe, err := m.GetFileSetFileByName(fe.EntryID)
				if err != nil {
					return fmt.Errorf("failed to parse entry %s: %v", filesetEntry, err)
				}
				ms = append(ms, mfe)
			}
		} else {
			ms = append(ms, m)
		}

		if err := ctrlc.Default.Run(context.Background(), func() error {
			for _, m := range ms {
				if entryStart {
					if main := m.GetLoadsByName("LC_MAIN"); len(main) == 0 {
						return fmt.Errorf("failed to find LC_MAIN in target when using --entry flag")
					} else {
						startAddr = main[0].(*macho.EntryPoint).EntryOffset + m.GetBaseAddress()
					}
				}
				if startAddr == 0 && startOff != 0 {
					if startAddr, err = m.GetVMAddress(startOff); err != nil {
						return fmt.Errorf("failed to get vmaddr for file offset %#x: %v", startOff, err)
					}
				}

				if !quiet {
					if len(cacheFile) == 0 {
						cacheFile = machoPath + ".a2s"
					}
				}

				if allFuncs && len(segmentSection) == 0 {
					for _, fn := range m.GetFunctions() {
						data, err := m.GetFunctionData(fn)
						if err != nil {
							log.Errorf("failed to get data for function: %v", err)
							continue
						}

						engine = disass.NewMachoDisass(m, &disass.Config{
							Data:         data,
							StartAddress: fn.StartAddr,
							Middle:       0,
							AsJSON:       asJSON,
							Demangle:     demangleFlag,
							Quite:        quiet,
							Color:        viper.GetBool("color") && !viper.GetBool("no-color"),
						})

						//***********************
						//* First pass ANALYSIS *
						//***********************
						if !quiet {
							if err := engine.OpenOrCreateSymMap(cacheFile, machoPath, viper.GetBool("macho.disass.replace")); err != nil {
								return fmt.Errorf("failed to open or create symbol map: %v", err)
							}
							if err := engine.Triage(); err != nil {
								return fmt.Errorf("first pass triage failed: %v", err)
							}
							if engine.EmptySymMap() {
								if err := engine.Analyze(); err != nil {
									if !viper.GetBool("macho.disass.force") {
										return fmt.Errorf("MachO analysis failed: %v (use --force to continue anyway)", err)
									}
								}
							}
							if err := engine.SaveAddrToSymMap(cacheFile); err != nil {
								log.Errorf("failed to save symbol map: %v", err)
							}
						}
						//***************
						//* DISASSEMBLE *
						//***************
						asm := disass.Disassemble(engine)
						if decompile {
							promptFmt, lexer, err := disass.GetPrompt(asm, viper.GetString("macho.disass.dec-lang"))
							if err != nil {
								return fmt.Errorf("failed to get prompt format string and syntax highlight lexer: %v", err)
							}
							llm, err := ai.NewAI(context.Background(), &ai.Config{
								Provider:    viper.GetString("macho.disass.llm"),
								Prompt:      fmt.Sprintf(promptFmt, asm),
								Model:       viper.GetString("macho.disass.dec-model"),
								Temperature: viper.GetFloat64("macho.disass.dec-temp"),
								TopP:        viper.GetFloat64("macho.disass.dec-top-p"),
								Stream:      true,
							})
							if err != nil {
								return fmt.Errorf("failed to create llm client: %v", err)
							}
							if !viper.IsSet("macho.disass.dec-model") {
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
				} else {
					if len(symbolName) > 0 {
						startAddr, err = m.FindSymbolAddress(symbolName)
						if err != nil {
							return err
						}
					} else if len(segmentSection) > 0 {
						parts := strings.Split(segmentSection, ".")
						if len(parts) != 2 {
							return fmt.Errorf("invalid --section format, must be segment.section")
						}
						if sec := m.Section(parts[0], parts[1]); sec != nil {
							startAddr = sec.Addr
							instructions = sec.Size / 4
						} else {
							return fmt.Errorf("failed to find section %s", segmentSection)
						}
					}
					// startAddr > 0 TODO: support slides
					// if slide > 0 {
					// 	startAddr = startAddr - slide
					// }

					/*
					 * Read in data to disassemble
					 */
					var data []byte
					if instructions > 0 {
						off, err := m.GetOffset(startAddr)
						if err != nil {
							return err
						}
						data = make([]byte, instructions*4)
						if _, err := m.ReadAt(data, int64(off)); err != nil {
							return err
						}
					} else {
						if fn, err := m.GetFunctionForVMAddr(startAddr); err == nil {
							soff, err := m.GetOffset(fn.StartAddr)
							if err != nil {
								return err
							}
							data = make([]byte, uint64(fn.EndAddr-fn.StartAddr))
							if _, err := m.ReadAt(data, int64(soff)); err != nil {
								return err
							}
							if startAddr != fn.StartAddr {
								middleAddr = startAddr
								startAddr = fn.StartAddr
							}
						} else {
							log.Warnf("disassembling 100 instructions at %#x", startAddr)
							instructions = 100
							off, err := m.GetOffset(startAddr)
							if err != nil {
								return err
							}
							data = make([]byte, instructions*4)
							if _, err := m.ReadAt(data, int64(off)); err != nil {
								return err
							}
						}
					}
					if len(data) == 0 {
						log.Fatal("failed to disassemble")
					}

					engine = disass.NewMachoDisass(m, &disass.Config{
						Data:         data,
						StartAddress: startAddr,
						Middle:       middleAddr,
						AsJSON:       asJSON,
						Demangle:     demangleFlag,
						Quite:        quiet,
						Color:        viper.GetBool("color") && !viper.GetBool("no-color"),
					})

					//***********************
					//* First pass ANALYSIS *
					//***********************
					if !quiet {
						if err := engine.OpenOrCreateSymMap(cacheFile, machoPath, viper.GetBool("macho.disass.replace")); err != nil {
							return fmt.Errorf("failed to open or create symbol map: %v", err)
						}
						if err := engine.Triage(); err != nil {
							return fmt.Errorf("first pass triage failed: %v", err)
						}
						// if engine.EmptySymMap() {
						if err := engine.Analyze(); err != nil {
							if !viper.GetBool("macho.disass.force") {
								return fmt.Errorf("MachO analysis failed: %v (use --force to continue anyway)", err)
							}
						}
						// }
						if entryStart {
							engine.SetStartSym(startAddr)
						}
						if err := engine.SaveAddrToSymMap(cacheFile); err != nil {
							log.Errorf("failed to save symbol map: %v", err)
						}
					}
					//***************
					//* DISASSEMBLE *
					//***************
					asm := disass.Disassemble(engine)
					if decompile {
						promptFmt, lexer, err := disass.GetPrompt(asm, viper.GetString("macho.disass.dec-lang"))
						if err != nil {
							return fmt.Errorf("failed to get prompt format string and syntax highlight lexer: %v", err)
						}
						llm, err := ai.NewAI(context.Background(), &ai.Config{
							Provider:    viper.GetString("macho.disass.llm"),
							Prompt:      fmt.Sprintf(promptFmt, asm),
							Model:       viper.GetString("macho.disass.dec-model"),
							Temperature: viper.GetFloat64("macho.disass.dec-temp"),
							TopP:        viper.GetFloat64("macho.disass.dec-top-p"),
							Stream:      true,
						})
						if err != nil {
							return fmt.Errorf("failed to create llm client: %v", err)
						}
						if !viper.IsSet("macho.disass.dec-model") {
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
		}); err != nil {
			if errors.As(err, &ctrlc.ErrorCtrlC{}) {
				if !quiet {
					if err := engine.SaveAddrToSymMap(cacheFile); err != nil {
						log.Errorf("failed to save symbol map: %v", err)
					}
				}
				log.Warn("exiting...")
			} else {
				return err
			}
		}
		return nil
	},
}
