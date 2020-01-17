// +build !windows,cgo

/*
Copyright © 2019 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/macho"
	"github.com/knightsc/gapstone"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(disCmd)

	disCmd.PersistentFlags().Uint64P("vaddr", "a", 0, "Virtual address to start disassembling")
	disCmd.PersistentFlags().Uint64P("instrs", "s", 20, "Number of instructions to disassemble")
}

// disCmd represents the dis command
var disCmd = &cobra.Command{
	Use:   "dis",
	Short: "Disassemble at address",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		startAddr, _ := cmd.Flags().GetUint64("vaddr")
		if startAddr == 0 {
			return fmt.Errorf("you must supply a vaddr to disassemble at")
		}

		instructions, _ := cmd.Flags().GetUint64("instrs")

		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(args[0])
		if err != nil {
			return err
		}

		data = make([]byte, 4*instructions)
		found := false
		for _, sec := range m.Sections {
			if sec.Name == "__text" {
				if sec.Addr < startAddr && startAddr < (sec.Addr+sec.Size) {
					found = true

					memOffset := startAddr - sec.Addr
					if instructions*4 > sec.Size-memOffset {
						data = make([]byte, sec.Size-memOffset)
					}

					_, err := sec.ReadAt(data, int64(memOffset))
					if err != nil {
						return err
					}

					break
				}
			}
		}

		if !found {
			return fmt.Errorf("supplied vaddr not found in any __text section")
		}

		engine, err := gapstone.New(
			gapstone.CS_ARCH_ARM64,
			gapstone.CS_MODE_ARM,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to create capstone engine")
		}

		insns, err := engine.Disasm(
			data,
			startAddr,
			0, // insns to disassemble, 0 for all
		)
		if err != nil {
			return errors.Wrapf(err, "failed to disassemble data")
		}

		for _, insn := range insns {
			fmt.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		}

		return nil
	},
}
