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

	classDumpCmd.Flags().StringP("theme", "t", "", "Color theme (nord, github, etc)")
	classDumpCmd.RegisterFlagCompletionFunc("theme", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return styles.Names(), cobra.ShellCompDirectiveNoFileComp
	})
	classDumpCmd.Flags().StringP("class", "c", "", "Dump class")
	classDumpCmd.Flags().StringP("proto", "p", "", "Dump protocol")
	classDumpCmd.Flags().StringP("cat", "a", "", "Dump category")
	classDumpCmd.MarkFlagsMutuallyExclusive("class", "proto", "cat")

	viper.BindPFlag("class-dump.class", classDumpCmd.Flags().Lookup("class"))
	viper.BindPFlag("class-dump.proto", classDumpCmd.Flags().Lookup("proto"))
	viper.BindPFlag("class-dump.cat", classDumpCmd.Flags().Lookup("cat"))
	viper.BindPFlag("class-dump.theme", classDumpCmd.Flags().Lookup("theme"))
}

// classDumpCmd represents the classDump command
var classDumpCmd = &cobra.Command{
	Use:     "class-dump [<DSC> <DYLIB>|<MACHO>]",
	Aliases: []string{"cd"},
	Short:   "ObjC class-dump a dylib from a DSC or MachO",
	Args:    cobra.MinimumNArgs(1),
	// ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// 	if len(args) == 1 {
	// 		return getImages(args[0]), cobra.ShellCompDirectiveDefault
	// 	}
	// 	return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	// },
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var m *macho.File

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		if ok, _ := magic.IsMachO(args[0]); ok {
			m, err := macho.Open(args[0])
			if err != nil {
				return err
			}
			defer m.Close()
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
		}

		switch {
		case viper.GetString("class-dump.class") != "":
			out, err := mcmd.GetClass(m, viper.GetString("class-dump.class"), &mcmd.Config{
				Color: viper.GetBool("color"),
				Theme: viper.GetString("class-dump.theme"),
			})
			if err != nil {
				return err
			}
			fmt.Println(out)
		case viper.GetString("class-dump.proto") != "":
			out, err := mcmd.GetProtocol(m, viper.GetString("class-dump.proto"), &mcmd.Config{
				Color: viper.GetBool("color"),
				Theme: viper.GetString("class-dump.theme"),
			})
			if err != nil {
				return err
			}
			fmt.Println(out)
		case viper.GetString("class-dump.cat") != "":
			out, err := mcmd.GetCategory(m, viper.GetString("class-dump.cat"), &mcmd.Config{
				Color: viper.GetBool("color"),
				Theme: viper.GetString("class-dump.theme"),
			})
			if err != nil {
				return err
			}
			fmt.Println(out)
		default:
			out, err := mcmd.Dump(m, &mcmd.Config{
				Color: viper.GetBool("color"),
				Theme: viper.GetString("class-dump.theme"),
			})
			if err != nil {
				return err
			}
			fmt.Println(out)
		}

		return nil
	},
}
