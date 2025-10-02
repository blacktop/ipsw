/*
Copyright © 2025 blacktop

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

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/diff"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(diffCmd)
	// diffCmd.Flags().StringP("in", "i", "", "Path to IPSW .idiff file")
	diffCmd.Flags().StringP("title", "t", "", "Title of the diff")
	diffCmd.Flags().BoolP("markdown", "m", false, "Save diff as Markdown file")
	diffCmd.Flags().Bool("json", false, "Save diff as JSON file")
	diffCmd.Flags().Bool("html", false, "Save diff as HTML file")
	diffCmd.Flags().StringArrayP("kdk", "k", []string{}, "Path to KDKs to diff")
	diffCmd.Flags().Bool("launchd", false, "Diff launchd configs")
	diffCmd.Flags().Bool("fw", false, "Diff other firmwares")
	diffCmd.Flags().Bool("feat", false, "Diff feature flags")
	diffCmd.Flags().Bool("files", false, "Diff files")
	diffCmd.Flags().Bool("strs", false, "Diff MachO cstrings")
	diffCmd.Flags().Bool("starts", false, "Diff MachO function starts")
	diffCmd.Flags().Bool("ent", false, "Diff MachO entitlements")
	diffCmd.Flags().StringSlice("allow-list", []string{}, "Filter MachO sections to diff (e.g. __TEXT.__text)")
	diffCmd.Flags().StringSlice("block-list", []string{}, "Remove MachO sections to diff (e.g. __TEXT.__info_plist)")
	diffCmd.Flags().StringP("signatures", "s", "", "Path to symbolicator signatures folder")
	diffCmd.MarkFlagDirname("signatures")
	diffCmd.Flags().StringP("output", "o", "", "Folder to save diff output")
	diffCmd.MarkFlagDirname("output")
	diffCmd.MarkFlagsMutuallyExclusive("markdown", "json", "html")
	// viper.BindPFlag("diff.in", diffCmd.Flags().Lookup("in"))
	viper.BindPFlag("diff.title", diffCmd.Flags().Lookup("title"))
	viper.BindPFlag("diff.markdown", diffCmd.Flags().Lookup("markdown"))
	viper.BindPFlag("diff.json", diffCmd.Flags().Lookup("json"))
	viper.BindPFlag("diff.html", diffCmd.Flags().Lookup("html"))
	viper.BindPFlag("diff.kdk", diffCmd.Flags().Lookup("kdk"))
	viper.BindPFlag("diff.launchd", diffCmd.Flags().Lookup("launchd"))
	viper.BindPFlag("diff.fw", diffCmd.Flags().Lookup("fw"))
	viper.BindPFlag("diff.feat", diffCmd.Flags().Lookup("feat"))
	viper.BindPFlag("diff.strs", diffCmd.Flags().Lookup("strs"))
	viper.BindPFlag("diff.starts", diffCmd.Flags().Lookup("starts"))
	viper.BindPFlag("diff.ent", diffCmd.Flags().Lookup("ent"))
	viper.BindPFlag("diff.files", diffCmd.Flags().Lookup("files"))
	viper.BindPFlag("diff.allow-list", diffCmd.Flags().Lookup("allow-list"))
	viper.BindPFlag("diff.block-list", diffCmd.Flags().Lookup("block-list"))
	viper.BindPFlag("diff.signatures", diffCmd.Flags().Lookup("signatures"))
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
			--kdk /Library/Developer/KDKs/KDK_15.0_24A5279h.kdk/System/Library/Kernels/kernel.release.t6031`),
	Args:          cobra.ExactArgs(2),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// verify flags
		if len(viper.GetStringSlice("diff.kdk")) > 0 && len(viper.GetStringSlice("diff.kdk")) != 2 {
			return fmt.Errorf("you must specify two KDKs to diff; example: --kdk <KDK1> --kdk <KDK2>")
		}

		d, err := diff.NewPipeline(&diff.Config{
			Title:        viper.GetString("diff.title"),
			IpswOld:      filepath.Clean(args[0]),
			IpswNew:      filepath.Clean(args[1]),
			KDKs:         viper.GetStringSlice("diff.kdk"),
			LaunchD:      viper.GetBool("diff.launchd"),
			Firmware:     viper.GetBool("diff.fw"),
			Features:     viper.GetBool("diff.feat"),
			Files:        viper.GetBool("diff.files"),
			CStrings:     viper.GetBool("diff.strs"),
			FuncStarts:   viper.GetBool("diff.starts"),
			Entitlements: viper.GetBool("diff.ent"),
			AllowList:    viper.GetStringSlice("diff.allow-list"),
			BlockList:    viper.GetStringSlice("diff.block-list"),
			Signatures:   viper.GetString("diff.signatures"),
			Output:       viper.GetString("diff.output"),
			Verbose:      Verbose,
		})
		if err != nil {
			return err
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
