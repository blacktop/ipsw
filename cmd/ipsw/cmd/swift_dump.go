/*
Copyright © 2024 blacktop

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
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(swiftDumpCmd)

	swiftDumpCmd.Flags().Bool("deps", false, "Dump imported private frameworks")
	swiftDumpCmd.Flags().Bool("demangle", false, "Demangle symbol names")
	swiftDumpCmd.Flags().Bool("all", false, "Dump all other Swift sections/info")
	swiftDumpCmd.Flags().BoolP("interface", "i", false, "🚧 Dump Swift Interface")
	swiftDumpCmd.Flags().StringP("output", "o", "", "🚧 Folder to write interface to")
	swiftDumpCmd.MarkFlagDirname("output")
	swiftDumpCmd.Flags().String("theme", "nord", "Color theme (nord, github, etc)")
	swiftDumpCmd.RegisterFlagCompletionFunc("theme", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return styles.Names(), cobra.ShellCompDirectiveNoFileComp
	})
	swiftDumpCmd.Flags().StringP("type", "y", "", "Dump type (regex)")
	swiftDumpCmd.Flags().StringP("proto", "p", "", "Dump protocol (regex)")
	swiftDumpCmd.Flags().StringP("ext", "e", "", "Dump extension (regex)")
	swiftDumpCmd.Flags().StringP("ass", "a", "", "Dump associated type (regex)")
	// swiftDumpCmd.Flags().Bool("re", false, "RE verbosity (with addresses)")
	swiftDumpCmd.Flags().String("arch", "", "Which architecture to use for fat/universal MachO")

	viper.BindPFlag("swift-dump.deps", swiftDumpCmd.Flags().Lookup("deps"))
	viper.BindPFlag("swift-dump.demangle", swiftDumpCmd.Flags().Lookup("demangle"))
	viper.BindPFlag("swift-dump.all", swiftDumpCmd.Flags().Lookup("all"))
	viper.BindPFlag("swift-dump.interface", swiftDumpCmd.Flags().Lookup("interface"))
	viper.BindPFlag("swift-dump.output", swiftDumpCmd.Flags().Lookup("output"))
	viper.BindPFlag("swift-dump.theme", swiftDumpCmd.Flags().Lookup("theme"))
	viper.BindPFlag("swift-dump.type", swiftDumpCmd.Flags().Lookup("type"))
	viper.BindPFlag("swift-dump.proto", swiftDumpCmd.Flags().Lookup("proto"))
	viper.BindPFlag("swift-dump.ext", swiftDumpCmd.Flags().Lookup("ext"))
	viper.BindPFlag("swift-dump.ass", swiftDumpCmd.Flags().Lookup("ass"))
	// viper.BindPFlag("swift-dump.re", swiftDumpCmd.Flags().Lookup("re"))
	viper.BindPFlag("swift-dump.arch", swiftDumpCmd.Flags().Lookup("arch"))
}

// swiftDumpCmd represents the swiftDump command
var swiftDumpCmd = &cobra.Command{
	Use:     "swift-dump [<DSC> <DYLIB>|<MACHO>]",
	Aliases: []string{"sd"},
	Short:   "🚧 Swift class-dump a dylib from a DSC or MachO",
	Args:    cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return getImages(args[0]), cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		var s *mcmd.Swift

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// Validate Flags
		if viper.GetBool("swift-dump.interface") &&
			(viper.GetString("swift-dump.type") != "" ||
				viper.GetString("swift-dump.proto") != "" ||
				viper.GetString("swift-dump.ext") != "") ||
			viper.GetString("swift-dump.ass") != "" {
			return fmt.Errorf("cannot dump --interface and use --type, --protocol, --ext or --ass flags")
		} else if len(viper.GetString("swift-dump.output")) > 0 && !viper.GetBool("swift-dump.interface") {
			return fmt.Errorf("cannot set --output without setting --interface")
		}

		if len(viper.GetString("swift-dump.output")) > 0 {
			if err := os.MkdirAll(viper.GetString("swift-dump.output"), 0o750); err != nil {
				return err
			}
		}

		doDemangle := viper.GetBool("swift-dump.demangle")

		conf := mcmd.SwiftConfig{
			Verbose: Verbose,
			// Addrs:       viper.GetBool("swift-dump.re"),
			All:         viper.GetBool("swift-dump.all"),
			Interface:   viper.GetBool("swift-dump.interface"),
			Deps:        viper.GetBool("swift-dump.deps"),
			Demangle:    doDemangle,
			IpswVersion: fmt.Sprintf("Version: %s, BuildCommit: %s", strings.TrimSpace(AppVersion), strings.TrimSpace(AppBuildCommit)),
			Color:       viper.GetBool("color") && !viper.GetBool("no-color"),
			Theme:       viper.GetString("swift-dump.theme"),
			Output:      viper.GetString("swift-dump.output"),
		}

		if ok, _ := magic.IsMachO(args[0]); ok { /* MachO binary */
			machoPath := filepath.Clean(args[0])
			// first check for fat file
			fat, err := macho.OpenFat(machoPath)
			if err != nil && err != macho.ErrNotFat {
				return err
			}
			if err == macho.ErrNotFat {
				m, err = macho.Open(machoPath)
				if err != nil {
					return err
				}
			} else {
				var options []string
				var shortOptions []string
				for _, arch := range fat.Arches {
					options = append(options, fmt.Sprintf("%s, %s", arch.CPU, arch.SubCPU.String(arch.CPU)))
					shortOptions = append(shortOptions, strings.ToLower(arch.SubCPU.String(arch.CPU)))
				}

				if len(viper.GetString("swift-dump.arch")) > 0 {
					found := false
					for i, opt := range shortOptions {
						if strings.Contains(strings.ToLower(opt), strings.ToLower(viper.GetString("swift-dump.arch"))) {
							m = fat.Arches[i].File
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("--arch '%s' not found in: %s", viper.GetString("swift-dump.arch"), strings.Join(shortOptions, ", "))
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
			if viper.GetBool("swift-dump.deps") {
				log.Error("cannot dump imported private frameworks from a MachO file (only from a DSC)")
			}

			conf.Name = filepath.Base(machoPath)

			s, err = mcmd.NewSwift(m, nil, &conf)
			if err != nil {
				return err
			}
		} else { /* DSC file */
			if len(args) < 2 {
				return fmt.Errorf("must provide an in-cache DYLIB to dump")
			}

			f, err := dyld.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()

			image, err := f.Image(args[1])
			if err != nil {
				return err
			}

			m, err = image.GetMacho()
			if err != nil {
				return err
			}

			image.ParseLocalSymbols(false) // parse local symbols for swift demangling
			if m.Symtab != nil {
				for idx, sym := range m.Symtab.Syms {
					if sym.Value != 0 {
						if sym.Name == "<redacted>" {
							if name, ok := f.AddressToSymbol[sym.Value]; ok {
								m.Symtab.Syms[idx].Name = name
							}
						}
					}
					if doDemangle {
						if strings.HasPrefix(sym.Name, "_$s") || strings.HasPrefix(sym.Name, "$s") {
							m.Symtab.Syms[idx].Name, _ = swift.Demangle(sym.Name)
						} else if strings.HasPrefix(sym.Name, "__Z") || strings.HasPrefix(sym.Name, "_Z") {
							m.Symtab.Syms[idx].Name = demangle.Do(sym.Name, false, false)
						}
					}
				}
			}

			conf.Name = filepath.Base(image.Name)

			s, err = mcmd.NewSwift(m, f, &conf)
			if err != nil {
				return err
			}
		}

		if viper.GetBool("swift-dump.interface") {
			return s.Interface()
		}

		if viper.GetString("swift-dump.type") != "" {
			if err := s.DumpType(viper.GetString("swift-dump.type")); err != nil {
				return err
			}
		}

		if viper.GetString("swift-dump.proto") != "" {
			if err := s.DumpProtocol(viper.GetString("swift-dump.proto")); err != nil {
				return err
			}
		}

		if viper.GetString("swift-dump.ext") != "" {
			if err := s.DumpExtension(viper.GetString("swift-dump.ext")); err != nil {
				return err
			}
		}

		if viper.GetString("swift-dump.ass") != "" {
			if err := s.DumpAssociatedType(viper.GetString("swift-dump.ass")); err != nil {
				return err
			}
		}

		if viper.GetString("swift-dump.type") == "" &&
			viper.GetString("swift-dump.proto") == "" &&
			viper.GetString("swift-dump.ext") == "" &&
			viper.GetString("swift-dump.ass") == "" {
			return s.Dump()
		}

		return nil
	},
}
