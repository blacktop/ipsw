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
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/commands/dwarf"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const dSymMachoPath = ".dSYM/Contents/Resources/DWARF"

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
			return nil, nil
		}
		return nil, err
	}
	kdks = selKDKs

	// Get kernel dSYMs from first KDK
	kernsGlob1, err := filepath.Glob(filepath.Join(kdks[0], "System/Library/Kernels/kernel*.dSYM"))
	if err != nil {
		return nil, err
	}
	if len(kernsGlob1) == 0 {
		return nil, fmt.Errorf("could not find kernel dSYMs in %s", kdks[0])
	}

	// Get kernel dSYMs from second KDK
	kernsGlob2, err := filepath.Glob(filepath.Join(kdks[1], "System/Library/Kernels/kernel*.dSYM"))
	if err != nil {
		return nil, err
	}
	if len(kernsGlob2) == 0 {
		return nil, fmt.Errorf("could not find kernel dSYMs in %s", kdks[1])
	}

	// Build set of kernel names from first KDK (strip .dSYM)
	kerns1 := make(map[string]bool)
	for _, k := range kernsGlob1 {
		kernelName := strings.TrimSuffix(filepath.Base(k), ".dSYM")
		kerns1[kernelName] = true
	}

	// Find common kernels (intersection) where dSYM exists in both
	var kerns []string
	for _, k := range kernsGlob2 {
		kernelName := strings.TrimSuffix(filepath.Base(k), ".dSYM")
		if kerns1[kernelName] {
			kerns = append(kerns, kernelName)
		}
	}

	if len(kerns) == 0 {
		return nil, fmt.Errorf("no common kernel dSYMs found between %s and %s", kdks[0], kdks[1])
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
			return nil, nil
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
			return "", nil
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
			return "", nil
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
	dwarfCmd.Flags().BoolP("md", "m", false, "Markdown diff output")
	dwarfCmd.Flags().Bool("no-off", false, "Do NOT display struct field offsets in output")
	dwarfCmd.Flags().StringP("type", "t", "", "Type to lookup")
	dwarfCmd.Flags().StringP("name", "n", "", "Name to lookup")
	dwarfCmd.Flags().Bool("all", false, "Dump all types")
	dwarfCmd.Flags().Bool("structs", false, "Dump all structs")
	dwarfCmd.Flags().Bool("enums", false, "Dump all enums")
	// viper.BindPFlag("kernel.dwarf.arch", dwarfCmd.Flags().Lookup("arch"))
	// viper.BindPFlag("kernel.dwarf.pretty", dwarfCmd.Flags().Lookup("pretty"))
	// viper.BindPFlag("kernel.dwarf.json", dwarfCmd.Flags().Lookup("json"))
	viper.BindPFlag("kernel.dwarf.diff", dwarfCmd.Flags().Lookup("diff"))
	viper.BindPFlag("kernel.dwarf.md", dwarfCmd.Flags().Lookup("md"))
	viper.BindPFlag("kernel.dwarf.no-off", dwarfCmd.Flags().Lookup("no-off"))
	viper.BindPFlag("kernel.dwarf.type", dwarfCmd.Flags().Lookup("type"))
	viper.BindPFlag("kernel.dwarf.name", dwarfCmd.Flags().Lookup("name"))
	viper.BindPFlag("kernel.dwarf.all", dwarfCmd.Flags().Lookup("all"))
	viper.BindPFlag("kernel.dwarf.structs", dwarfCmd.Flags().Lookup("structs"))
	viper.BindPFlag("kernel.dwarf.enums", dwarfCmd.Flags().Lookup("enums"))
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
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		// selectedArch := viper.GetString("kernel.dwarf.arch")
		// prettyJSON := viper.GetBool("kernel.dwarf.pretty")
		// outAsJSON := viper.GetBool("kernel.dwarf.json")
		doDiff := viper.GetBool("kernel.dwarf.diff")
		noOffsets := viper.GetBool("kernel.dwarf.no-off")
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
				t1, err := dwarf.GetType(filepath.Clean(args[0]), viper.GetString("kernel.dwarf.type"), !noOffsets)
				if err != nil {
					return err
				}

				t2, err := dwarf.GetType(filepath.Clean(args[1]), viper.GetString("kernel.dwarf.type"), !noOffsets)
				if err != nil {
					return err
				}

				if len(t1) == 0 || len(t2) == 0 {
					return fmt.Errorf("could not find type '%s' in one or both of the files", viper.GetString("kernel.dwarf.type"))
				}

				for file2, typ2 := range t2 {
					if typ1, found := t1[file2]; found {
						out, err := utils.GitDiff(typ1, typ2,
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
					}
				}
			} else { // diff ALL structs
				out, err := dwarf.DiffEnums(filepath.Clean(args[0]), filepath.Clean(args[1]), &dwarf.Config{
					Markdown:    viper.GetBool("kernel.dwarf.md"),
					Color:       colors.Active(),
					DiffTool:    viper.GetString("diff-tool"),
					ShowOffsets: !noOffsets,
				})
				if err != nil {
					return fmt.Errorf("failed diffing enums: %s", err)
				}
				if len(out) > 0 {
					log.Info("Diffing all enums")
					fmt.Println(out)
				}
				log.Info("Diffing all structs")
				out, err = dwarf.DiffStructures(filepath.Clean(args[0]), filepath.Clean(args[1]), &dwarf.Config{
					Markdown:    viper.GetBool("kernel.dwarf.md"),
					Color:       colors.Active(),
					DiffTool:    viper.GetString("diff-tool"),
					ShowOffsets: !noOffsets,
				})
				if err != nil {
					return fmt.Errorf("failed diffing structs: %s", err)
				}
				fmt.Println(out)
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
			typs, err := dwarf.GetType(filepath.Clean(args[0]), viper.GetString("kernel.dwarf.type"), !noOffsets)
			if err != nil {
				return err
			}
			for file, typ := range typs {
				if len(file) > 0 {
					if _, after, ok := strings.Cut(file, "/Library/Caches/com.apple.xbs/"); ok {
						log.WithField("file", after).Info(viper.GetString("kernel.dwarf.type"))
					} else {
						log.WithField("file", file).Info(viper.GetString("kernel.dwarf.type"))
					}
				}
				fmt.Println(utils.ClangFormat(typ, viper.GetString("kernel.dwarf.type")+".h", colors.Active()))
			}
		}

		if len(viper.GetString("kernel.dwarf.name")) > 0 {
			names, err := dwarf.GetName(filepath.Clean(args[0]), viper.GetString("kernel.dwarf.name"))
			if err != nil {
				return err
			}
			for file, n := range names {
				if _, after, ok := strings.Cut(file, "/Library/Caches/com.apple.xbs/"); ok {
					log.WithField("file", after).Info(viper.GetString("kernel.dwarf.name"))
				} else {
					log.WithField("file", file).Info(viper.GetString("kernel.dwarf.name"))
				}
				if n.Name == "" {
					if strings.HasPrefix(n.LinkageName, "__Z") || strings.HasPrefix(n.LinkageName, "_Z") {
						n.LinkageName = demangle.Do("_"+n.LinkageName, false, false)
					}
					fmt.Printf("%#x: %s", n.LowPC, utils.ClangFormat(n.LinkageName, viper.GetString("kernel.dwarf.name")+".h", colors.Active()))
				} else {
					fmt.Printf("%#x: %s", n.LowPC, utils.ClangFormat(n.String(), viper.GetString("kernel.dwarf.name")+".h", colors.Active()))
				}
			}
		}

		if viper.GetBool("kernel.dwarf.all") {
			if err := dwarf.DumpAllTypes(filepath.Clean(args[0]), &dwarf.Config{
				Markdown:    viper.GetBool("kernel.dwarf.md"),
				Color:       colors.Active(),
				DiffTool:    viper.GetString("diff-tool"),
				ShowOffsets: !noOffsets,
			}); err != nil {
				return fmt.Errorf("failed to dump all: %v", err)
			}
		}
		if viper.GetBool("kernel.dwarf.structs") {
			if err := dwarf.DumpAllStructs(filepath.Clean(args[0]), &dwarf.Config{
				Markdown:    viper.GetBool("kernel.dwarf.md"),
				Color:       colors.Active(),
				DiffTool:    viper.GetString("diff-tool"),
				ShowOffsets: !noOffsets,
			}); err != nil {
				return fmt.Errorf("failed to dump structs: %v", err)
			}
		}
		if viper.GetBool("kernel.dwarf.enums") {
			if err := dwarf.DumpAllEnums(filepath.Clean(args[0]), &dwarf.Config{
				Markdown:    viper.GetBool("kernel.dwarf.md"),
				Color:       colors.Active(),
				DiffTool:    viper.GetString("diff-tool"),
				ShowOffsets: !noOffsets,
			}); err != nil {
				return fmt.Errorf("failed to dump enums: %v", err)
			}
		}

		return nil
	},
}
