/*
Copyright © 2018-2022 blacktop

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
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoDisassCmd)
	// machoDisassCmd.Flags().Uint64("slide", 0, "MachO slide to remove from --vaddr")
	machoDisassCmd.Flags().StringP("symbol", "s", "", "Function to disassemble")
	machoDisassCmd.Flags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	machoDisassCmd.Flags().Uint64P("count", "c", 0, "Number of instructions to disassemble")
	machoDisassCmd.Flags().BoolP("demangle", "d", false, "Demangle symbol names")
	machoDisassCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	machoDisassCmd.Flags().BoolP("quiet", "q", false, "Do NOT markup analysis (Faster)")
	machoDisassCmd.Flags().Bool("color", false, "Syntax highlight assembly output")
	// machoDisassCmd.Flags().StringP("input", "i", "", "Input function JSON file")
	machoDisassCmd.Flags().String("cache", "", "Path to .a2s addr to sym cache file (speeds up analysis)")

	viper.BindPFlag("macho.disass.symbol", machoDisassCmd.Flags().Lookup("symbol"))
	viper.BindPFlag("macho.disass.vaddr", machoDisassCmd.Flags().Lookup("vaddr"))
	viper.BindPFlag("macho.disass.count", machoDisassCmd.Flags().Lookup("count"))
	viper.BindPFlag("macho.disass.demangle", machoDisassCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("macho.disass.json", machoDisassCmd.Flags().Lookup("json"))
	viper.BindPFlag("macho.disass.quiet", machoDisassCmd.Flags().Lookup("quiet"))
	viper.BindPFlag("macho.disass.color", machoDisassCmd.Flags().Lookup("color"))
	// viper.BindPFlag("macho.disass.input", machoDisassCmd.Flags().Lookup("input"))
	viper.BindPFlag("macho.disass.cache", machoDisassCmd.Flags().Lookup("cache"))

	machoDisassCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoDisassCmd represents the dis command
var machoDisassCmd = &cobra.Command{
	Use:          "disass <MACHO>",
	Short:        "Disassemble ARM64 MachO at symbol/vaddr",
	Args:         cobra.MinimumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		var middleAddr uint64
		var symbolMap map[uint64]string

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		symbolName := viper.GetString("macho.disass.symbol")
		startAddr := viper.GetUint64("macho.disass.vaddr")
		instructions := viper.GetUint64("macho.disass.count")

		demangleFlag := viper.GetBool("macho.disass.demangle")
		asJSON := viper.GetBool("macho.disass.json")
		quiet := viper.GetBool("macho.disass.quiet")
		forceColor := viper.GetBool("macho.disass.color")

		// funcFile := viper.GetString("macho.disass.input")
		cacheFile := viper.GetString("macho.disass.cache")

		if forceColor {
			color.NoColor = false
		}

		// funcFile, _ := cmd.Flags().GetString("input")
		allFuncs := false

		if len(symbolName) > 0 && startAddr != 0 {
			return fmt.Errorf("you can only use --symbol OR --vaddr (not both)")
		} else if len(symbolName) == 0 && startAddr == 0 {
			allFuncs = true
			// return fmt.Errorf("you must supply a --symbol OR --vaddr to disassemble")
		}

		machoPath := filepath.Clean(args[0])

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
			for _, arch := range fat.Arches {
				if strings.Contains(strings.ToLower(arch.SubCPU.String(arch.CPU)), "arm64") {
					m = arch.File
					break
				}
			}
		}

		if !strings.Contains(strings.ToLower(m.FileHeader.SubCPU.String(m.CPU)), "arm64") {
			log.Errorf("can only disassemble arm64 binaries")
			return nil
		}

		if len(cacheFile) > 0 {
			a2sFile, err := os.Open(cacheFile)
			if err != nil {
				return errors.Wrapf(err, "failed to open companion file")
			}
			// Decoding the serialized data
			err = gob.NewDecoder(a2sFile).Decode(&symbolMap)
			if err != nil {
				return err
			}
		} else {
			symbolMap = make(map[uint64]string)
		}

		if allFuncs {
			for _, fn := range m.GetFunctions() {
				data, err := m.GetFunctionData(fn)
				if err != nil {
					log.Errorf("failed to get data for function: %v", err)
					continue
				}

				engine := disass.NewMachoDisass(m, &symbolMap, &disass.Config{
					Data:         data,
					StartAddress: fn.StartAddr,
					Middle:       0,
					AsJSON:       asJSON,
					Demangle:     demangleFlag,
					Quite:        quiet,
					Color:        forceColor,
				})

				//***********************
				//* First pass ANALYSIS *
				//***********************
				if err := engine.Triage(); err != nil {
					return fmt.Errorf("first pass triage failed: %v", err)
				}
				if len(symbolMap) == 0 {
					if err := engine.Analyze(); err != nil {
						return fmt.Errorf("MachO analysis failed: %v", err)
					}
				}
				//***************
				//* DISASSEMBLE *
				//***************
				disass.Disassemble(engine)
			}
		} else {
			if len(symbolName) > 0 {
				startAddr, err = m.FindSymbolAddress(symbolName)
				if err != nil {
					return err
				}
			} else { // startAddr > 0
				// if slide > 0 {
				// 	startAddr = startAddr - slide
				// }
			}

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
			if len(data) > 0 {
				log.Fatal("failed to disassemble")
			}

			engine := disass.NewMachoDisass(m, &symbolMap, &disass.Config{
				Data:         data,
				StartAddress: startAddr,
				Middle:       middleAddr,
				AsJSON:       asJSON,
				Demangle:     demangleFlag,
				Quite:        quiet,
				Color:        forceColor,
			})

			//***********************
			//* First pass ANALYSIS *
			//***********************
			if err := engine.Triage(); err != nil {
				return fmt.Errorf("first pass triage failed: %v", err)
			}
			if err := engine.Analyze(); err != nil {
				return fmt.Errorf("MachO analysis failed: %v", err)
			}
			//***************
			//* DISASSEMBLE *
			//***************
			disass.Disassemble(engine)
		}

		return nil
	},
}
