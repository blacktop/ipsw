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
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().StringP("in", "i", "", "Path to IPSW .idiff file")
	diffCmd.Flags().StringP("title", "t", "", "Title of the diff")
	diffCmd.Flags().BoolP("markdown", "m", false, "Save diff as Markdown file")
	diffCmd.Flags().Bool("json", false, "Save diff as JSON file")
	diffCmd.Flags().Bool("html", false, "Save diff as HTML file")
	diffCmd.Flags().StringArrayP("kdk", "k", []string{}, "Path to KDKs to diff")
	diffCmd.Flags().Bool("launchd", false, "Diff launchd configs")
	diffCmd.Flags().Bool("fw", false, "Diff other firmwares")
	diffCmd.Flags().StringSliceP("filter", "f", []string{}, "Filter MachO sections to diff (e.g. __TEXT.__text)")
	diffCmd.Flags().StringP("output", "o", "", "Folder to save diff output")
	diffCmd.MarkFlagDirname("output")
	diffCmd.MarkFlagsMutuallyExclusive("markdown", "json", "html")
	viper.BindPFlag("diff.in", diffCmd.Flags().Lookup("in"))
	viper.BindPFlag("diff.title", diffCmd.Flags().Lookup("title"))
	viper.BindPFlag("diff.markdown", diffCmd.Flags().Lookup("markdown"))
	viper.BindPFlag("diff.json", diffCmd.Flags().Lookup("json"))
	viper.BindPFlag("diff.html", diffCmd.Flags().Lookup("html"))
	viper.BindPFlag("diff.kdk", diffCmd.Flags().Lookup("kdk"))
	viper.BindPFlag("diff.launchd", diffCmd.Flags().Lookup("launchd"))
	viper.BindPFlag("diff.fw", diffCmd.Flags().Lookup("fw"))
	viper.BindPFlag("diff.filter", diffCmd.Flags().Lookup("filter"))
	viper.BindPFlag("diff.output", diffCmd.Flags().Lookup("output"))
}

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff <IPSW> <IPSW>",
	Short: "Diff IPSWs",
	Example: heredoc.Doc(`
		# Diff two IPSWs
		❯ ipsw diff <old.ipsw> <new.ipsw> --fw --launchd --output <output/folder> --markdown
		# Diff two IPSWs with KDKs
		❯ ipsw diff <old.ipsw> <new.ipsw> --output <output/folder> --markdown 
			--kdk /Library/Developer/KDKs/KDK_15.0_24A5264n.kdk/System/Library/Kernels/kernel.release.t6031 
			--kdk /Library/Developer/KDKs/KDK_15.0_24A5279h.kdk/System/Library/Kernels/kernel.release.t6031
		# Use a previously saved .idiff file
		❯ ipsw diff --in <path/to/.idiff> --output <output/folder> --markdown`),
	Args:          cobra.MaximumNArgs(2),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// verify flags
		if !viper.IsSet("diff.in") && len(args) != 2 {
			return fmt.Errorf("you must specify two IPSWs to diff OR a .idiff file via the --in flag")
		} else if viper.IsSet("diff.in") && len(args) != 0 {
			return fmt.Errorf("you cannot specify both an --in .idiff file AND IPSWs to diff")
		} else if viper.IsSet("diff.kdk") && len(viper.GetStringSlice("diff.kdk")) != 2 {
			return fmt.Errorf("you must specify two KDKs to diff; example: --kdk <KDK1> --kdk <KDK2>")
		}

		var d *diff.Diff

		if viper.IsSet("diff.in") {
			idiff, err := os.Open(viper.GetString("diff.in"))
			if err != nil {
				return fmt.Errorf("failed to open .idiff file: %w", err)
			}
			defer idiff.Close()
			if err := gob.NewDecoder(idiff).Decode(&d); err != nil {
				return fmt.Errorf("failed to decode .idiff file '%s': %w", idiff.Name(), err)
			}
			// override output folder
			d.SetOutput(viper.GetString("diff.output"))
		} else {
			if len(args) != 2 {
				return fmt.Errorf("you must specify two IPSWs to diff")
			}
			d = diff.New(&diff.Config{
				Title:    viper.GetString("diff.title"),
				IpswOld:  filepath.Clean(args[0]),
				IpswNew:  filepath.Clean(args[1]),
				KDKs:     viper.GetStringSlice("diff.kdk"),
				LaunchD:  viper.GetBool("diff.launchd"),
				Firmware: viper.GetBool("diff.fw"),
				Filter:   viper.GetStringSlice("diff.filter"),
				Output:   viper.GetString("diff.output"),
			})
			if err := d.Diff(); err != nil {
				return err
			}
		}

		if viper.IsSet("diff.output") {
			switch {
			case viper.GetBool("diff.markdown"):
				if err := d.Markdown(); err != nil {
					return fmt.Errorf("failed to save Markdown diff: %s", err)
				}
			case viper.GetBool("diff.json"):
				if err := d.ToJSON(); err != nil {
					return fmt.Errorf("failed to create JSON diff: %s", err)
				}
			case viper.GetBool("diff.html"):
				if err := d.ToHTML(); err != nil {
					return fmt.Errorf("failed to save HTML diff: %s", err)
				}
			default:
				if err := d.Save(); err != nil {
					return fmt.Errorf("failed to save diff: %w", err)
				}
			}
		} else {
			fmt.Println(d.String())
		}

		return nil
	},
}
