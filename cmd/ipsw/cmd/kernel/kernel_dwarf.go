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
package kernel

import (
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	dwf "github.com/blacktop/go-dwarf"
	"github.com/blacktop/go-macho"
	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getStructType(path, name string) (*dwf.StructType, error) {
	m, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return nil, err
	}

	r := df.Reader()

	off, err := df.LookupType(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find type %s: %v", name, err)
	}

	r.Seek(off)

	entry, err := r.Next()
	if err != nil {
		return nil, err
	}

	var st *dwf.StructType
	if entry.Tag == dwf.TagStructType {
		typ, err := df.Type(entry.Offset)
		if err != nil {
			return nil, err
		}
		st = typ.(*dwf.StructType)
		if st.Incomplete {
			return nil, fmt.Errorf("type %s is incomplete", name)
		}
	} else {
		return nil, fmt.Errorf("did not find tag struct type: found %s", entry.Tag)
	}

	return st, nil
}

func init() {
	KernelcacheCmd.AddCommand(dwarfCmd)

	dwarfCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	dwarfCmd.Flags().BoolP("pretty", "", false, "Pretty print JSON")
	dwarfCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	dwarfCmd.Flags().BoolP("diff", "d", false, "Diff two structs")
	dwarfCmd.Flags().StringP("type", "t", "", "Type to lookup")
	dwarfCmd.Flags().StringP("name", "n", "", "Name to lookup")
	viper.BindPFlag("kernel.dwarf.arch", dwarfCmd.Flags().Lookup("arch"))
	viper.BindPFlag("kernel.dwarf.pretty", dwarfCmd.Flags().Lookup("pretty"))
	viper.BindPFlag("kernel.dwarf.json", dwarfCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.dwarf.diff", dwarfCmd.Flags().Lookup("diff"))
	viper.BindPFlag("kernel.dwarf.type", dwarfCmd.Flags().Lookup("type"))
	viper.BindPFlag("kernel.dwarf.name", dwarfCmd.Flags().Lookup("name"))
	dwarfCmd.MarkZshCompPositionalArgumentFile(1)
}

// dwarfCmd represents the dwarf command
var dwarfCmd = &cobra.Command{
	Use:           "dwarf",
	Short:         "Dump DWARF debug information",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  false,
	SilenceErrors: true,
	Aliases:       []string{"dwarfdump"},
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		// selectedArch := viper.GetString("kernel.dwarf.arch")
		// prettyJSON := viper.GetBool("kernel.dwarf.pretty")
		// outAsJSON := viper.GetBool("kernel.dwarf.json")
		doDiff := viper.GetBool("kernel.dwarf.diff")

		t1, err := getStructType(filepath.Clean(args[0]), viper.GetString("kernel.dwarf.type"))
		if err != nil {
			return err
		}

		if !doDiff {
			fmt.Println(t1.Defn())
		} else {
			if len(args) < 2 {
				return fmt.Errorf("you must supply 2 KDK kernelcaches to diff")
			}

			t2, err := getStructType(filepath.Clean(args[1]), viper.GetString("kernel.dwarf.type"))
			if err != nil {
				return err
			}

			if t1 == nil || t2 == nil {
				return fmt.Errorf("could not find type '%s' in either file", viper.GetString("kernel.dwarf.type"))
			}

			dmp := diffmatchpatch.New()

			diffs := dmp.DiffMain(t1.Defn(), t2.Defn(), false)
			if len(diffs) > 2 {
				diffs = dmp.DiffCleanupSemantic(diffs)
				diffs = dmp.DiffCleanupEfficiency(diffs)
			}
			if len(diffs) == 1 {
				if diffs[0].Type == diffmatchpatch.DiffEqual {
					log.Info("No differences found")
				}
			} else {
				log.Info("Differences found")
				fmt.Println(dmp.DiffPrettyText(diffs))
			}
		}

		return nil
	},
}
