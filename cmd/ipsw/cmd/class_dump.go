/*
Copyright © 2023 blacktop

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

	"github.com/apex/log"

	"github.com/alecthomas/chroma/v2/styles"
	"github.com/blacktop/go-macho"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(classDumpCmd)

	classDumpCmd.Flags().Bool("headers", false, "Dump ObjC headers")
	classDumpCmd.Flags().StringP("output", "o", "", "Folder to write headers to")
	classDumpCmd.MarkFlagDirname("output")
	classDumpCmd.Flags().StringP("theme", "t", "nord", "Color theme (nord, github, etc)")
	classDumpCmd.RegisterFlagCompletionFunc("theme", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return styles.Names(), cobra.ShellCompDirectiveNoFileComp
	})
	classDumpCmd.Flags().StringP("class", "c", "", "Dump class (regex)")
	classDumpCmd.Flags().StringP("proto", "p", "", "Dump protocol (regex)")
	classDumpCmd.Flags().StringP("cat", "a", "", "Dump category (regex)")
	classDumpCmd.Flags().Bool("refs", false, "Dump ObjC references too")
	classDumpCmd.Flags().Bool("re", false, "RE verbosity (with addresses)")

	viper.BindPFlag("class-dump.headers", classDumpCmd.Flags().Lookup("headers"))
	viper.BindPFlag("class-dump.output", classDumpCmd.Flags().Lookup("output"))
	viper.BindPFlag("class-dump.class", classDumpCmd.Flags().Lookup("class"))
	viper.BindPFlag("class-dump.proto", classDumpCmd.Flags().Lookup("proto"))
	viper.BindPFlag("class-dump.cat", classDumpCmd.Flags().Lookup("cat"))
	viper.BindPFlag("class-dump.theme", classDumpCmd.Flags().Lookup("theme"))
	viper.BindPFlag("class-dump.refs", classDumpCmd.Flags().Lookup("refs"))
	viper.BindPFlag("class-dump.re", classDumpCmd.Flags().Lookup("re"))
}

// classDumpCmd represents the classDump command
var classDumpCmd = &cobra.Command{
	Use:     "class-dump [<DSC> <DYLIB>|<MACHO>]",
	Aliases: []string{"cd"},
	Short:   "ObjC class-dump a dylib from a DSC or a MachO binary",
	Args:    cobra.MinimumNArgs(1),
	// ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// 	if len(args) == 1 {
	// 		return getImages(args[0]), cobra.ShellCompDirectiveDefault
	// 	}
	// 	return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	// },
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var name string
		var m *macho.File

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		if viper.GetBool("class-dump.headers") &&
			(viper.GetString("class-dump.class") != "" ||
				viper.GetString("class-dump.proto") != "" ||
				viper.GetString("class-dump.cat") != "") {
			return fmt.Errorf("cannot dump --headers and use --class, --protocol or --category flags")
		}

		if len(viper.GetString("class-dump.output")) > 0 {
			if err := os.MkdirAll(viper.GetString("class-dump.output"), 0o750); err != nil {
				return err
			}
		}

		if ok, _ := magic.IsMachO(args[0]); ok {
			m, err := macho.Open(args[0])
			if err != nil {
				return err
			}
			defer m.Close()

			name = filepath.Base(args[0])
		} else {
			f, err := dyld.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()

			if len(args) < 2 {
				return fmt.Errorf("must provide an in-cache DYLIB to dump")
			}

			img, err := f.Image(args[1])
			if err != nil {
				return err
			}

			m, err = img.GetMacho()
			if err != nil {
				return err
			}

			name = filepath.Base(img.Name)
		}

		var buildVersions []string
		if bvers := m.GetLoadsByName("LC_BUILD_VERSION"); len(bvers) > 0 {
			for _, bv := range bvers {
				buildVersions = append(buildVersions, bv.String())
			}
		}
		var sourceVersion string
		if svers := m.GetLoadsByName("LC_SOURCE_VERSION"); len(svers) > 0 {
			sourceVersion = svers[0].String()
		}

		conf := mcmd.Config{
			Name:          name,
			Verbose:       Verbose,
			Addrs:         viper.GetBool("class-dump.re"),
			ObjcRefs:      viper.GetBool("class-dump.refs"),
			IpswVersion:   fmt.Sprintf("Version: %s, BuildTime: %s", strings.TrimSpace(AppVersion), strings.TrimSpace(AppBuildTime)),
			BuildVersions: buildVersions,
			SourceVersion: sourceVersion,
			Color:         viper.GetBool("color"),
			Theme:         viper.GetString("class-dump.theme"),
			Output:        viper.GetString("class-dump.output"),
		}

		if viper.GetBool("class-dump.headers") {
			return mcmd.Headers(m, &conf)
		}

		if viper.GetString("class-dump.class") != "" {
			if err := mcmd.DumpClass(m, viper.GetString("class-dump.class"), &conf); err != nil {
				return err
			}
		}

		if viper.GetString("class-dump.proto") != "" {
			if err := mcmd.DumpProtocol(m, viper.GetString("class-dump.proto"), &conf); err != nil {
				return err
			}
		}

		if viper.GetString("class-dump.cat") != "" {
			if err := mcmd.DumpCategory(m, viper.GetString("class-dump.cat"), &conf); err != nil {
				return err
			}
		}

		if viper.GetString("class-dump.class") == "" &&
			viper.GetString("class-dump.proto") == "" &&
			viper.GetString("class-dump.cat") == "" {
			if err := mcmd.Dump(m, &conf); err != nil {
				return err
			}
		}

		return nil
	},
}
