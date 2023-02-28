/*
Copyright © 2018-2023 blacktop

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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	dwf "github.com/blacktop/go-dwarf"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const dSymMachoPath = ".dSYM/Contents/Resources/DWARF"

func getAllStructs(path string) (<-chan *dwf.StructType, error) {
	out := make(chan *dwf.StructType)

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

	go func() {
		for {
			entry, err := r.Next()
			if err != nil {
				break
			}
			if entry == nil {
				break
			}

			var st *dwf.StructType
			if entry.Tag == dwf.TagStructType {
				typ, err := df.Type(entry.Offset)
				if err != nil {
					continue
				}
				st = typ.(*dwf.StructType)
				if st.Incomplete {
					continue
				}
				out <- st
			}
		}
		close(out)
	}()

	return out, nil
}

func getName(path, name string) (*dwf.FuncType, error) {
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

	off, err := df.LookupName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find name %s: %v", name, err)
	}

	r.Seek(off)

	entry, err := r.Next()
	if err != nil {
		return nil, err
	}

	var ft *dwf.FuncType
	if entry.Tag == dwf.TagSubprogram || entry.Tag == dwf.TagSubroutineType || entry.Tag == dwf.TagInlinedSubroutine {
		typ, err := df.Type(entry.Offset)
		if err != nil {
			return nil, err
		}
		ft = typ.(*dwf.FuncType)
	} else {
		typ, err := df.Type(entry.Offset)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("did not find tag func type: found %s; %s", entry.Tag, typ.String())
	}

	return ft, nil
}

func getType(path, name string) (typeStr string, filename string, err error) {
	m, err := macho.Open(path)
	if err != nil {
		return "", "", err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return "", "", err
	}

	r := df.Reader()

	off, err := df.LookupType(name)
	if err != nil {
		return "", "", fmt.Errorf("failed to find type %s: %v", name, err)
	}

	r.Seek(off)

	entry, err := r.Next()
	if err != nil {
		return "", "", err
	}

	fs, err := df.FilesForEntry(entry)
	if err != nil {
		return "", "", fmt.Errorf("failed to get files for entry: %v", err)
	}
	if idx, ok := entry.Val(dwf.AttrDeclFile).(int64); ok {
		if idx < int64(len(fs)) {
			filename = fs[idx].Name
		}
	}

	typ, err := df.Type(entry.Offset)
	if err != nil {
		return "", "", fmt.Errorf("failed to get type for entry: %v", err)
	}

	switch t := typ.(type) {
	case *dwf.StructType:
		if t.Incomplete {
			return "", "", fmt.Errorf("type %s is incomplete", name)
		}
		return t.Defn(), filename, nil
	case *dwf.ArrayType:
		return t.String(), filename, nil
	case *dwf.PtrType:
		return t.String(), filename, nil
	case *dwf.FuncType:
		return t.String(), filename, nil
	case *dwf.EnumType:
		return t.String(), filename, nil
	case *dwf.TypedefType:
		if enum, ok := t.Type.(*dwf.EnumType); ok {
			return fmt.Sprintf("typedef %s %s;", enum.String(), t.Name), filename, nil
		}
		return fmt.Sprintf("typedef %s %s;", t.Type.Common().Name, t.Name), filename, nil
	default:
		return "", "", fmt.Errorf("did not find supported type: found %s; %s", entry.Tag, typ.String())
	}
}

func selectKDKs() ([]string, error) {
	kdks, err := filepath.Glob("/Library/Developer/KDKs/KDK*")
	if err != nil {
		return nil, err
	}

	if len(kdks) < 2 {
		return nil, fmt.Errorf("you must supply 2 KDK kernelcaches to diff")
	}

	selKDKs := []string{}
	prompt := &survey.MultiSelect{
		Message:  "Which KDKs would you like to diff (select 2):",
		Options:  kdks,
		PageSize: 15,
	}
	if err := survey.AskOne(prompt, &selKDKs, survey.WithValidator(survey.MinItems(2)), survey.WithValidator(survey.MaxItems(2))); err != nil {
		if err == terminal.InterruptErr {
			log.Warn("Exiting...")
			os.Exit(0)
		}
		return nil, err
	}
	kdks = selKDKs

	kernsGlob, err := filepath.Glob(filepath.Join(kdks[0], "System/Library/Kernels/kernel*"))
	if err != nil {
		return nil, err
	}
	if len(kernsGlob) == 0 {
		return nil, fmt.Errorf("could not find kernel in %s", kdks[0])
	}

	// filter out .dSYM
	var kerns []string
	for _, k := range kernsGlob {
		if strings.HasSuffix(k, ".dSYM") {
			continue
		}
		kerns = append(kerns, filepath.Base(k))
	}

	var kern string
	prompt2 := &survey.Select{
		Message:  "Choose a kernel type to diff:",
		Options:  kerns,
		PageSize: 15,
	}
	if err := survey.AskOne(prompt2, &kern); err != nil {
		if err == terminal.InterruptErr {
			log.Warn("Exiting...")
			os.Exit(0)
		}
		return nil, err
	}

	args := []string{
		filepath.Join(kdks[0], "System/Library/Kernels", kern+dSymMachoPath, filepath.Base(kern)),
		filepath.Join(kdks[1], "System/Library/Kernels", kern+dSymMachoPath, filepath.Base(kern)),
	}

	return args, nil
}

func selectKDK() (string, error) {
	kdks, err := filepath.Glob("/Library/Developer/KDKs/KDK*")
	if err != nil {
		return "", err
	}

	if len(kdks) == 0 {
		return "", fmt.Errorf("failed to find any KDKs in /Library/Developer/KDKs")
	}

	var selKDK string
	prompt := &survey.Select{
		Message:  "Which KDKs would you like to use:",
		Options:  kdks,
		PageSize: 15,
	}
	if err := survey.AskOne(prompt, &selKDK); err != nil {
		if err == terminal.InterruptErr {
			log.Warn("Exiting...")
			os.Exit(0)
		}
		return "", err
	}

	kernsGlob, err := filepath.Glob(filepath.Join(selKDK, "System/Library/Kernels/kernel*"))
	if err != nil {
		return "", err
	}
	if len(kernsGlob) == 0 {
		return "", fmt.Errorf("could not find kernels in %s", selKDK)
	}

	// filter out .dSYM
	var kerns []string
	for _, k := range kernsGlob {
		if strings.HasSuffix(k, ".dSYM") {
			continue
		}
		kerns = append(kerns, filepath.Base(k))
	}

	var kern string
	prompt = &survey.Select{
		Message:  "Choose a kernel type to diff:",
		Options:  kerns,
		PageSize: 15,
	}
	if err := survey.AskOne(prompt, &kern); err != nil {
		if err == terminal.InterruptErr {
			log.Warn("Exiting...")
			os.Exit(0)
		}
		return "", err
	}

	return filepath.Join(selKDK, "System/Library/Kernels", kern+".dSYM/Contents/Resources/DWARF", kern), nil
}

func init() {
	KernelcacheCmd.AddCommand(dwarfCmd)

	// dwarfCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	// dwarfCmd.Flags().BoolP("pretty", "", false, "Pretty print JSON")
	// dwarfCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	dwarfCmd.Flags().BoolP("diff", "d", false, "Diff two structs")
	dwarfCmd.Flags().StringP("type", "t", "", "Type to lookup")
	dwarfCmd.Flags().StringP("name", "n", "", "Name to lookup")
	// viper.BindPFlag("kernel.dwarf.arch", dwarfCmd.Flags().Lookup("arch"))
	// viper.BindPFlag("kernel.dwarf.pretty", dwarfCmd.Flags().Lookup("pretty"))
	// viper.BindPFlag("kernel.dwarf.json", dwarfCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.dwarf.diff", dwarfCmd.Flags().Lookup("diff"))
	viper.BindPFlag("kernel.dwarf.type", dwarfCmd.Flags().Lookup("type"))
	viper.BindPFlag("kernel.dwarf.name", dwarfCmd.Flags().Lookup("name"))
	dwarfCmd.MarkZshCompPositionalArgumentFile(1)
}

// dwarfCmd represents the dwarf command
var dwarfCmd = &cobra.Command{
	Use:     "dwarf <dSYM> [dSYM]",
	Aliases: []string{"dwarfdump", "dd"},
	Short:   "🚧 Dump DWARF debug information",
	Example: `# Dump the task struct
❯ ipsw kernel dwarf -t task /Library/Developer/KDKs/KDK_13.3_22E5230e.kdk/System/Library/Kernels/kernel.development.t6020.dSYM
# Diff task struct
❯ ipsw kernel dwarf --type task --diff
# Diff ALL structs
❯ ipsw kernel dwarf --diff`,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		// selectedArch := viper.GetString("kernel.dwarf.arch")
		// prettyJSON := viper.GetBool("kernel.dwarf.pretty")
		// outAsJSON := viper.GetBool("kernel.dwarf.json")
		doDiff := viper.GetBool("kernel.dwarf.diff")
		// validate args
		if len(viper.GetString("kernel.dwarf.type")) > 0 && len(viper.GetString("kernel.dwarf.name")) > 0 {
			return fmt.Errorf("cannot specify both --type and --name")
		}

		if doDiff {
			if len(args) < 2 {
				if runtime.GOOS == "darwin" {
					kdks, err := selectKDKs()
					if err != nil {
						return err
					}
					args = append(args, kdks...)
				} else {
					return fmt.Errorf("diff requires two KDK .dSYM(s) to diff")
				}
			} else {
				if filepath.Ext(args[0]) == ".dSYM" {
					args[0] = filepath.Join(args[0], "Contents", "Resources", "DWARF", filepath.Base(strings.TrimSuffix(args[0], filepath.Ext(args[0]))))
				}
				if filepath.Ext(args[1]) == ".dSYM" {
					args[1] = filepath.Join(args[1], "Contents", "Resources", "DWARF", filepath.Base(strings.TrimSuffix(args[1], filepath.Ext(args[1]))))
				}
			}

			if len(viper.GetString("kernel.dwarf.type")) > 0 {
				t1, _, err := getType(filepath.Clean(args[0]), viper.GetString("kernel.dwarf.type"))
				if err != nil {
					return err
				}

				t2, _, err := getType(filepath.Clean(args[1]), viper.GetString("kernel.dwarf.type"))
				if err != nil {
					return err
				}

				if t1 == "" || t2 == "" {
					return fmt.Errorf("could not find type '%s' in one or both of the files", viper.GetString("kernel.dwarf.type"))
				}

				out, err := utils.GitDiff(t1, t2, &utils.GitDiffConfig{Color: viper.GetBool("color")})
				if err != nil {
					return err
				}

				if len(out) == 0 {
					log.Info("No differences found")
				} else {
					log.Info("Differences found")
					fmt.Println(out)
				}
			} else { // diff ALL structs
				log.Info("Diffing all structs")
				m, err := macho.Open(args[0])
				if err != nil {
					return err
				}
				defer m.Close()

				df, err := m.DWARF()
				if err != nil {
					return err
				}

				r := df.Reader()

				types, err := getAllStructs(filepath.Clean(args[1]))
				if err != nil {
					return err
				}

				seen := make(map[string]bool)

				for t := range types {
					if len(t.StructName) > 0 {
						if _, ok := seen[t.StructName]; !ok {
							seen[t.StructName] = true
							off, err := df.LookupType(t.StructName)
							if err != nil {
								log.WithField("struct", t.StructName).Info("NEW")
								println()
								fmt.Println(utils.ClangFormat(t.Defn(), t.StructName+".h", viper.GetBool("color")))
								continue // not found in older version
							}

							r.Seek(off)

							entry, err := r.Next()
							if err != nil {
								return err
							}

							var st *dwf.StructType
							if entry.Tag == dwf.TagStructType {
								typ, err := df.Type(entry.Offset)
								if err != nil {
									return err
								}
								st = typ.(*dwf.StructType)
								if st.Incomplete {
									continue
								}
								out, err := utils.GitDiff(st.Defn(), t.Defn(), &utils.GitDiffConfig{Color: viper.GetBool("color")})
								if err != nil {
									return err
								}
								if len(out) > 0 {
									log.WithField("struct", t.StructName).Warn("DIFF")
									fmt.Println(out)
								}
							}
						}
					}
				}
			}

			return nil
		}

		if len(args) == 0 {
			if runtime.GOOS == "darwin" {
				aKDK, err := selectKDK()
				if err != nil {
					return err
				}
				args = append(args, aKDK)
			} else {
				return fmt.Errorf("requires a KDK .dSYM to process")
			}
		} else {
			input := strings.TrimSuffix(args[0], "/") // remove trailing slash (in case user added one via tab completion)
			if filepath.Ext(input) == ".dSYM" {
				args[0] = filepath.Join(input, "Contents", "Resources", "DWARF", filepath.Base(strings.TrimSuffix(input, filepath.Ext(input))))
			}
		}

		if len(viper.GetString("kernel.dwarf.type")) > 0 {
			typstr, file, err := getType(filepath.Clean(args[0]), viper.GetString("kernel.dwarf.type"))
			if err != nil {
				return err
			}
			if len(file) > 0 {
				if _, after, ok := strings.Cut(file, "/Library/Caches/com.apple.xbs/Sources/"); ok {
					log.WithField("file", after).Info(viper.GetString("kernel.dwarf.type"))
				} else {
					log.WithField("file", file).Info(viper.GetString("kernel.dwarf.type"))
				}
			}
			fmt.Println(utils.ClangFormat(typstr, viper.GetString("kernel.dwarf.type")+".h", viper.GetBool("color")))
		}

		if len(viper.GetString("kernel.dwarf.name")) > 0 {
			n, err := getName(filepath.Clean(args[0]), viper.GetString("kernel.dwarf.name"))
			if err != nil {
				return err
			}
			fmt.Println(utils.ClangFormat(n.String(), viper.GetString("kernel.dwarf.name")+".h", viper.GetBool("color")))
		}

		return nil
	},
}
