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
package kernel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/colors"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ctf"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(ctfdumpCmd)

	ctfdumpCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	ctfdumpCmd.Flags().BoolP("pretty", "", false, "Pretty print JSON")
	ctfdumpCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	ctfdumpCmd.Flags().BoolP("diff", "d", false, "Diff two structs")
	viper.BindPFlag("kernel.ctfdump.arch", ctfdumpCmd.Flags().Lookup("arch"))
	viper.BindPFlag("kernel.ctfdump.pretty", ctfdumpCmd.Flags().Lookup("pretty"))
	viper.BindPFlag("kernel.ctfdump.json", ctfdumpCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.ctfdump.diff", ctfdumpCmd.Flags().Lookup("diff"))
	ctfdumpCmd.MarkZshCompPositionalArgumentFile(1)
}

// ctfdumpCmd represents the ctfdump command
var ctfdumpCmd = &cobra.Command{
	Use:           "ctfdump",
	Aliases:       []string{"c", "ctf"},
	Short:         "Dump CTF info",
	Args:          cobra.MinimumNArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File

		// flags
		selectedArch := viper.GetString("kernel.ctfdump.arch")
		prettyJSON := viper.GetBool("kernel.ctfdump.pretty")
		outAsJSON := viper.GetBool("kernel.ctfdump.json")
		doDiff := viper.GetBool("kernel.ctfdump.diff")

		machoPath := filepath.Clean(args[0])

		if _, err := os.Stat(machoPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", machoPath)
		}

		// Use the helper to handle fat/universal files
		m1, err := mcmd.OpenMachO(machoPath, selectedArch)
		if err != nil {
			return err
		}
		defer m1.Close()
		m = m1.File

		c, err := ctf.Parse(m)
		if err != nil {
			return err
		}

		ids := make([]int, 0, len(c.Types))
		for id := range c.Types {
			ids = append(ids, id)
		}
		sort.Ints(ids)

		if doDiff {
			// TODO: DRY this shiz up!
			if len(args) < 3 {
				return fmt.Errorf("must provide two files to diff and a struct to compare")
			}

			var t1 ctf.Type
			var t2 ctf.Type

			machoPath2 := filepath.Clean(args[1])

			if _, err := os.Stat(machoPath2); os.IsNotExist(err) {
				return fmt.Errorf("file %s does not exist", machoPath2)
			}

			// Use the helper to handle fat/universal files
			mr, err := mcmd.OpenMachO(machoPath2, selectedArch)
			if err != nil {
				return err
			}
			defer mr.Close()
			m = mr.File

			c2, err := ctf.Parse(m)
			if err != nil {
				return err
			}

			ids2 := make([]int, 0, len(c2.Types))
			for id := range c2.Types {
				ids2 = append(ids2, id)
			}
			sort.Ints(ids2)

			for _, id := range ids {
				if c.Types[id].Name() == args[2] {
					t1 = c.Types[id]
					break
				}
			}

			for _, id := range ids2 {
				if c2.Types[id].Name() == args[2] {
					t2 = c2.Types[id]
					break
				}
			}

			if t1 == nil || t2 == nil {
				return fmt.Errorf("could not find struct '%s' in either file", args[2])
			}

			out, err := utils.GitDiff(
				t1.String(),
				t2.String(),
				&utils.GitDiffConfig{
					Color: colors.Active(),
					Tool: viper.GetString("diff-tool"),
				})
			if err != nil {
				return err
			}
			if len(out) == 0 {
				log.Info("No differences found")
			} else {
				log.Info("Differences found")
				fmt.Println(out)
			}
		} else if len(args) > 1 {
			for _, id := range ids {
				if c.Types[id].Name() == args[1] {
					fmt.Println(c.Types[id])
					break
				}
			}
		} else { // DUMP
			if outAsJSON {
				var b []byte

				if prettyJSON {
					b, err = json.MarshalIndent(c, "", "    ")
					if err != nil {
						return fmt.Errorf("failed to marshal function as JSON: %v", err)
					}
				} else {
					b, err = json.Marshal(c)
					if err != nil {
						return fmt.Errorf("failed to marshal function as JSON: %v", err)
					}
				}

				kver, err := kernelcache.GetVersion(m)
				if err != nil {
					return fmt.Errorf("failed to get kernel version: %v", err)
				}

				cwd, _ := os.Getwd()
				fileName := fmt.Sprintf("ctfdump-%s.json", kver.KernelVersion.XNU)
				log.Infof("Creating %s", filepath.Join(cwd, fileName))
				if err := os.WriteFile(fileName, b, 0660); err != nil {
					return err
				}
			} else {
				fmt.Printf("- CTF Header -----------------------------------------------------------------\n\n")
				fmt.Println(c.Header)
				fmt.Printf("\n- Types ----------------------------------------------------------------------\n\n")
				for _, id := range ids {
					fmt.Println(c.Types[id].Dump())
				}
				fmt.Printf("\n- Data Objects ---------------------------------------------------------------\n\n")
				for _, g := range c.Globals {
					fmt.Println(g)
				}
				fmt.Printf("\n- Functions ------------------------------------------------------------------\n\n")
				for _, f := range c.Functions {
					fmt.Println(f)
				}
			}
		}

		return nil
	},
}
