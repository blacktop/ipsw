/*
Copyright © 2026 blacktop

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
	diffCmd.Flags().BoolP("markdown", "m", false, "Output diff as Markdown")
	diffCmd.Flags().Bool("json", false, "Output diff as JSON")
	diffCmd.Flags().Bool("html", false, "Output diff as HTML")
	diffCmd.Flags().StringArrayP("kdk", "k", []string{}, "Path to KDKs to diff")
	diffCmd.Flags().Bool("launchd", false, "Diff launchd configs")
	diffCmd.Flags().Bool("fw", false, "Diff other firmwares")
	diffCmd.Flags().Bool("feat", false, "Diff feature flags")
	diffCmd.Flags().Bool("files", false, "Diff files")
	diffCmd.Flags().Bool("strs", false, "Diff MachO cstrings")
	diffCmd.Flags().Bool("starts", false, "Diff MachO function starts")
	diffCmd.Flags().Bool("ent", false, "Diff MachO entitlements")
	diffCmd.Flags().Bool("low-memory", false, "Use disk caching to reduce RAM usage")
	diffCmd.Flags().StringSlice("allow-list", []string{}, "Filter MachO sections to diff (e.g. __TEXT.__text)")
	diffCmd.Flags().StringSlice("block-list", []string{}, "Remove MachO sections to diff (e.g. __TEXT.__info_plist)")
	registerDiffSandboxFlags(diffCmd)
	diffCmd.Flags().StringP("signatures", "s", "", "Path to symbolicator signatures folder")
	diffCmd.MarkFlagDirname("signatures")
	diffCmd.Flags().StringP("output", "o", "", "Folder to save diff output")
	diffCmd.MarkFlagDirname("output")
	diffCmd.Flags().String("key-db", "", "Path to AEA keys JSON database (for OTA diffs)")
	diffCmd.MarkFlagFilename("key-db", "json")
	diffCmd.Flags().String("key-val", "", "Base64 encoded AEA symmetric encryption key (for OTA diffs)")
	diffCmd.Flags().Bool("insecure", false, "Allow insecure connections when fetching AEA keys")
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
	viper.BindPFlag("diff.low-memory", diffCmd.Flags().Lookup("low-memory"))
	viper.BindPFlag("diff.files", diffCmd.Flags().Lookup("files"))
	viper.BindPFlag("diff.allow-list", diffCmd.Flags().Lookup("allow-list"))
	viper.BindPFlag("diff.block-list", diffCmd.Flags().Lookup("block-list"))
	viper.BindPFlag("diff.signatures", diffCmd.Flags().Lookup("signatures"))
	viper.BindPFlag("diff.output", diffCmd.Flags().Lookup("output"))
	viper.BindPFlag("diff.key-db", diffCmd.Flags().Lookup("key-db"))
	viper.BindPFlag("diff.key-val", diffCmd.Flags().Lookup("key-val"))
	viper.BindPFlag("diff.insecure", diffCmd.Flags().Lookup("insecure"))
}

func outputDiff(d *diff.Diff, hasOutput, markdownOut, jsonOut, htmlOut bool) error {
	switch {
	case markdownOut:
		if hasOutput {
			if err := d.Markdown(); err != nil {
				return fmt.Errorf("failed to save Markdown diff: %s", err)
			}
			return nil
		}
		fmt.Println(d.String())
	case jsonOut:
		if err := d.ToJSON(); err != nil {
			return fmt.Errorf("failed to output JSON diff: %s", err)
		}
	case htmlOut:
		if err := d.ToHTML(); err != nil {
			return fmt.Errorf("failed to output HTML diff: %s", err)
		}
	case hasOutput:
		if err := d.Save(); err != nil {
			return fmt.Errorf("failed to save diff: %w", err)
		}
	default:
		fmt.Println(d.String())
	}

	return nil
}

// diffCmd represents the diff command
var diffCmd = &cobra.Command{
	Use:   "diff <IPSW|OTA|DIR> <IPSW|OTA|DIR>",
	Short: "Diff IPSWs, OTAs, or patched OTA DMG directories",
	Example: heredoc.Doc(`
		# Diff two IPSWs
		❯ ipsw diff <old.ipsw> <new.ipsw> --fw --launchd --output <output/folder> --markdown
		# Diff two OTAs (darwin only, requires full OTAs)
		❯ ipsw diff <old.ota> <new.ota> --output <output/folder> --markdown
		# Diff two OTAs with AEA key database
		❯ ipsw diff <old.ota> <new.ota> --key-db keys.json --output <output/folder> --markdown
		# Diff two ota patch rsr output directories
		❯ ipsw diff <old_rsr_dir> <new_rsr_dir> --files --output <output/folder> --markdown
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
		if err := diffSandboxPreflight(); err != nil {
			return err
		}

		d := diff.New(&diff.Config{
			Title:        viper.GetString("diff.title"),
			IpswOld:      filepath.Clean(args[0]),
			IpswNew:      filepath.Clean(args[1]),
			KDKs:         viper.GetStringSlice("diff.kdk"),
			LaunchD:      viper.GetBool("diff.launchd"),
			Firmware:     viper.GetBool("diff.fw"),
			Features:     viper.GetBool("diff.feat"),
			Files:        viper.GetBool("diff.files"),
			Sandbox:      diffSandboxEnabled(),
			CStrings:     viper.GetBool("diff.strs"),
			FuncStarts:   viper.GetBool("diff.starts"),
			Entitlements: viper.GetBool("diff.ent"),
			AllowList:    viper.GetStringSlice("diff.allow-list"),
			BlockList:    viper.GetStringSlice("diff.block-list"),
			Signatures:   viper.GetString("diff.signatures"),
			Output:       viper.GetString("diff.output"),
			Verbose:      Verbose,
			LowMemory:    viper.GetBool("diff.low-memory"),
			AEAKeyDB:     viper.GetString("diff.key-db"),
			AEAKeyVal:    viper.GetString("diff.key-val"),
			AEAInsecure:  viper.GetBool("diff.insecure"),
		})
		if err := d.Diff(); err != nil {
			return err
		}

		markdownOut := viper.GetBool("diff.markdown")
		jsonOut := viper.GetBool("diff.json")
		htmlOut := viper.GetBool("diff.html")
		hasOutput := viper.GetString("diff.output") != ""

		if err := outputDiff(d, hasOutput, markdownOut, jsonOut, htmlOut); err != nil {
			return err
		}

		return nil
	},
}
