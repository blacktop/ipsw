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
package fw

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/iboot"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FwCmd.AddCommand(ibootCmd)

	ibootCmd.Flags().Bool("version", false, "Print version")
	ibootCmd.Flags().BoolP("strings", "s", false, "Print strings")
	ibootCmd.Flags().IntP("min", "m", 5, "Minimum length of string to print")
	ibootCmd.Flags().BoolP("remote", "r", false, "Parse remote IPSW URL")
	ibootCmd.Flags().BoolP("flat", "f", false, "Do NOT preserve directory structure when extracting im4p files")
	ibootCmd.Flags().StringP("output", "o", "", "Folder to extract files to")
	ibootCmd.MarkFlagDirname("output")
	viper.BindPFlag("fw.iboot.version", ibootCmd.Flags().Lookup("version"))
	viper.BindPFlag("fw.iboot.strings", ibootCmd.Flags().Lookup("strings"))
	viper.BindPFlag("fw.iboot.min", ibootCmd.Flags().Lookup("min"))
	viper.BindPFlag("fw.iboot.remote", ibootCmd.Flags().Lookup("remote"))
	viper.BindPFlag("fw.iboot.flat", ibootCmd.Flags().Lookup("flat"))
	viper.BindPFlag("fw.iboot.output", ibootCmd.Flags().Lookup("output"))
}

// ibootCmd represents the iboot command
var ibootCmd = &cobra.Command{
	Use:           "iboot <IPSW|URL|IM4P>",
	Aliases:       []string{"ib"},
	Short:         "Dump iBoot files",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		showVersion := viper.GetBool("fw.iboot.version")
		showStrings := viper.GetBool("fw.iboot.strings")
		minLen := viper.GetInt("fw.iboot.min")
		flat := viper.GetBool("fw.iboot.flat")
		output := viper.GetString("fw.iboot.output")
		infile := filepath.Clean(args[0])
		// validate flags
		if showStrings && showVersion {
			return fmt.Errorf("cannot set both --strings and --version flags")
		}
		if minLen < iboot.MinStringLength {
			return fmt.Errorf("minimum string length must be at least %d", iboot.MinStringLength)
		}
		if !viper.IsSet("fw.iboot.output") {
			output = filepath.Dir(infile)
		} else {
			output = filepath.Clean(output)
			if err := os.MkdirAll(output, 0o755); err != nil {
				return fmt.Errorf("failed to create output directory: %v", err)
			}
		}

		dowork := func(im4p *img4.Payload, outputDir string) error {
			iboot, err := iboot.Parse(im4p.Data)
			if err != nil {
				return fmt.Errorf("failed to parse iboot data: %v", err)
			}

			var names []string
			for name := range iboot.Files {
				names = append(names, name)
			}
			sort.Strings(names)

			if showVersion {
				fmt.Println(iboot.String())
			} else if showStrings {
				fmt.Printf("%s %s Strings\n", iboot.Version, iboot.Release)
				fmt.Println("======================================")
				for _, offset := range slices.Sorted(maps.Keys(iboot.Strings["iboot"])) {
					if len(iboot.Strings["iboot"][offset]) < minLen {
						continue
					}
					fmt.Printf("0x%08X: %s\n", offset, iboot.Strings["iboot"][offset])
				}
				for _, name := range names {
					if name == "iboot" {
						continue
					}
					fmt.Printf("\n%s Strings\n", name)
					fmt.Println("========================")
					for _, offset := range slices.Sorted(maps.Keys(iboot.Strings[name])) {
						if len(iboot.Strings[name][offset]) < minLen {
							continue
						}
						fmt.Printf("0x%08X: %s\n", offset, iboot.Strings[name][offset])
					}
				}
			} else {
				fname := filepath.Join(outputDir, fmt.Sprintf("%s_%s.bin", iboot.Version, iboot.Release))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Dumping %s", fname))
				if err := os.WriteFile(fname, im4p.Data, 0o755); err != nil {
					return fmt.Errorf("failed to write file: %v", err)
				}
				for _, name := range names {
					fname := filepath.Join(outputDir, name)
					utils.Indent(log.Info, 2)(fmt.Sprintf("Dumping %s", fname))
					if err := os.WriteFile(fname, iboot.Files[name], 0o755); err != nil {
						return fmt.Errorf("failed to write file: %v", err)
					}
				}
			}

			return nil
		}

		if isZip, err := magic.IsZip(infile); err != nil && !viper.GetBool("fw.iboot.remote") {
			return fmt.Errorf("failed to determine if file is a zip: %v", err)
		} else if isZip || viper.GetBool("fw.iboot.remote") {
			var out []string
			if viper.GetBool("fw.iboot.remote") {
				out, err = extract.Search(&extract.Config{
					URL:     args[0],
					Pattern: "iBoot\\..*\\.im4p$",
					Flatten: flat,
					Output:  output,
				})
				if err != nil {
					return fmt.Errorf("failed to search for a iboot remote IPSW: %v", err)
				}
			} else {
				out, err = extract.Search(&extract.Config{
					IPSW:    infile,
					Pattern: "iBoot\\..*\\.im4p$",
					Flatten: flat,
					Output:  output,
				})
				if err != nil {
					return fmt.Errorf("failed to search for iboot in local IPSW: %v", err)
				}
			}
			for _, f := range out {
				im4p, err := img4.OpenPayload(f)
				if err != nil {
					return fmt.Errorf("failed to open im4p: %v", err)
				}
				if err := dowork(im4p, filepath.Dir(f)); err != nil {
					return err
				}
				os.Remove(f) // cleanup the extracted im4p file
			}
		} else if ok, _ := magic.IsIm4p(args[0]); ok {
			im4p, err := img4.OpenPayload(infile)
			if err != nil {
				return err
			}
			return dowork(im4p, output)
		} else {
			return fmt.Errorf("unsupported file type: %s", infile)
		}

		return nil
	},
}
