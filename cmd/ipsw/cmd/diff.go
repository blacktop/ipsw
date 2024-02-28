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
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().StringP("title", "t", "", "Title of the diff")
	diffCmd.Flags().Bool("html", false, "Save diff as HTML file")
	diffCmd.Flags().Bool("json", false, "Save diff as JSON file")
	diffCmd.Flags().StringArrayP("kdk", "k", []string{}, "Path to KDKs to diff")
	diffCmd.Flags().Bool("launchd", false, "Diff launchd configs")
	diffCmd.Flags().Bool("fw", false, "Diff other firmwares")
	diffCmd.Flags().StringSliceP("filter", "f", []string{}, "Filter MachO sections to diff (e.g. __TEXT.__text)")
	diffCmd.Flags().StringP("output", "o", "", "Folder to save diff output")
	diffCmd.MarkFlagDirname("output")
	viper.BindPFlag("diff.title", diffCmd.Flags().Lookup("title"))
	viper.BindPFlag("diff.html", diffCmd.Flags().Lookup("html"))
	viper.BindPFlag("diff.json", diffCmd.Flags().Lookup("json"))
	viper.BindPFlag("diff.kdk", diffCmd.Flags().Lookup("kdk"))
	viper.BindPFlag("diff.launchd", diffCmd.Flags().Lookup("launchd"))
	viper.BindPFlag("diff.fw", diffCmd.Flags().Lookup("fw"))
	viper.BindPFlag("diff.filter", diffCmd.Flags().Lookup("filter"))
	viper.BindPFlag("diff.output", diffCmd.Flags().Lookup("output"))
}

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:           "diff <IPSW> <IPSW>",
	Short:         "Diff IPSWs",
	Args:          cobra.ExactArgs(2),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetBool("diff.html") && viper.GetString("diff.output") == "" {
			return fmt.Errorf("you must specify an --output folder when saving as HTML")
		} else if viper.GetBool("diff.html") && viper.GetBool("diff.json") {
			return fmt.Errorf("you cannot save as both --html and --json")
		}

		if len(viper.GetStringSlice("diff.kdk")) > 0 && len(viper.GetStringSlice("diff.kdk")) != 2 {
			return fmt.Errorf("you must specify two KDKs to diff; example: --kdk <KDK1> --kdk <KDK2>")
		}

		d := diff.New(&diff.Config{
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

		if viper.GetBool("diff.json") {
			if err := d.ToJSON(); err != nil {
				log.Errorf("failed to create JSON diff: %s", err)
			}
			return nil
		}

		if viper.GetString("diff.output") != "" {
			if viper.GetBool("diff.html") {
				if err := d.ToHTML(); err != nil {
					log.Errorf("failed to save HTML diff: %s", err)
				}
			}
			return d.Save()
		}

		fmt.Println(d)

		return nil
	},
}
