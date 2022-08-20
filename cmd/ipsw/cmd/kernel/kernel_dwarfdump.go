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
	"io"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	dwf "github.com/blacktop/go-dwarf"
	"github.com/blacktop/go-macho"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(dwarfCmd)

	dwarfCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	dwarfCmd.Flags().BoolP("pretty", "", false, "Pretty print JSON")
	dwarfCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	dwarfCmd.Flags().BoolP("diff", "d", false, "Diff two structs")
	viper.BindPFlag("kernel.dwarf.arch", dwarfCmd.Flags().Lookup("arch"))
	viper.BindPFlag("kernel.dwarf.pretty", dwarfCmd.Flags().Lookup("pretty"))
	viper.BindPFlag("kernel.dwarf.json", dwarfCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.dwarf.diff", dwarfCmd.Flags().Lookup("diff"))
	dwarfCmd.MarkZshCompPositionalArgumentFile(1)
}

// dwarfCmd represents the dwarf command
var dwarfCmd = &cobra.Command{
	Use:           "dwarfdump",
	Short:         "Dump DWARF debug information",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		// var m2 *macho.File

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		// selectedArch := viper.GetString("kernel.dwarf.arch")
		// prettyJSON := viper.GetBool("kernel.dwarf.pretty")
		// outAsJSON := viper.GetBool("kernel.dwarf.json")
		// doDiff := viper.GetBool("kernel.dwarf.diff")

		machoPath := filepath.Clean(args[0])

		// if _, err := os.Stat(machoPath); os.IsNotExist(err) {
		// 	return fmt.Errorf("file %s does not exist", machoPath)
		// }

		// // first check for fat file
		// fat, err := macho.OpenFat(machoPath)
		// if err != nil && err != macho.ErrNotFat {
		// 	return err
		// }

		// if err == macho.ErrNotFat {
		// 	m, err = macho.Open(machoPath)
		// 	if err != nil {
		// 		return err
		// 	}
		// } else {
		// 	var options []string
		// 	var shortOptions []string
		// 	for _, arch := range fat.Arches {
		// 		options = append(options, fmt.Sprintf("%s, %s", arch.CPU, arch.SubCPU.String(arch.CPU)))
		// 		shortOptions = append(shortOptions, strings.ToLower(arch.SubCPU.String(arch.CPU)))
		// 	}

		// 	if len(selectedArch) > 0 {
		// 		found := false
		// 		for i, opt := range shortOptions {
		// 			if strings.Contains(strings.ToLower(opt), strings.ToLower(selectedArch)) {
		// 				m = fat.Arches[i].File
		// 				found = true
		// 				break
		// 			}
		// 		}
		// 		if !found {
		// 			return fmt.Errorf("--arch '%s' not found in: %s", selectedArch, strings.Join(shortOptions, ", "))
		// 		}

		// 	} else {
		// 		choice := 0
		// 		prompt := &survey.Select{
		// 			Message: "Detected a universal MachO file, please select an architecture to analyze:",
		// 			Options: options,
		// 		}
		// 		survey.AskOne(prompt, &choice)
		// 		m = fat.Arches[choice].File
		// 	}
		// }

		// bi := proc.NewBinaryInfo("darwin", "arm64")
		// bi.LoadBinaryInfo(machoPath, 0, nil)

		// typs, _ := bi.Types()
		// for _, typ := range typs {
		// 	fmt.Println(typ)
		// }

		// str, pos, fn := bi.PCToLine(0xFFFFFE0007434F34)
		// fmt.Println(str, pos, fn)

		// prettyPrint := func(s string) string {
		// 	// clang-format -style='{AlignConsecutiveDeclarations: true}' --assume-filename thread.h | bat -l c --tabs 0 -p --theme Nord --wrap=never --pager "less -S"'
		// 	cmd := exec.Command("clang-format", "-style='{AlignConsecutiveDeclarations: true}'", "-assume-filename", "thread.h")
		// 	cmd.Stdin = strings.NewReader(s)
		// 	var out bytes.Buffer
		// 	cmd.Stdout = &out
		// 	if err := cmd.Run(); err != nil {
		// 		log.Fatal(err.Error())
		// 	}
		// 	return out.String()
		// }

		m, err := macho.Open(machoPath)
		if err != nil {
			return err
		}

		df, err := m.DWARF()
		if err != nil {
			return err
		}

		r := df.Reader()

		for {
			entry, err := r.Next()
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}

			if entry == nil {
				break
			}

			// if entry.Tag == dwf.TagSubprogram {
			// 	lr, _ := df.LineReader(entry)
			// 	fmt.Println(lr)
			// }

			// if typ, err := df.Type(entry.Offset); err == nil {
			// 	if fn, ok := typ.(*dwf.FuncType); ok {
			// 		fmt.Println(fn)
			// 	}
			// }

			// Check if this entry is a function
			// if entry.Tag == dwf.TagSubprogram {

			// 	// Go through fields
			// 	for _, field := range entry.Field {

			// 		if field.Attr == dwf.AttrName {
			// 			fmt.Println(field.Val.(string))
			// 		}
			// 	}
			// }

			if entry.Tag == dwf.TagStructType {
				typ, err := df.Type(entry.Offset)
				if err != nil {
					return err
				}
				t1 := typ.(*dwf.StructType)
				if strings.EqualFold(t1.StructName, "thread") {
					if !t1.Incomplete {
						fmt.Println(t1.Defn())
					}
				}
				// // Go through fields
				// for _, field := range entry.Field {

				// 	if field.Attr == dwf.AttrName {
				// 		if field.Val.(string) == "thread_t" {
				// 			fmt.Println(field.Val.(string))
				// 		}
				// 		fmt.Println(field.Val.(string))
				// 	}
				// }
			}

		}

		return nil
	},
}
