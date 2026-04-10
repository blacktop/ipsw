//go:build darwin

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
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/notif"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(notifCmd)

	notifCmd.Flags().StringP("app", "a", "", "Filter by bundle identifier (e.g. com.apple.Messages)")
	notifCmd.Flags().Bool("apps", false, "List bundle identifiers with record counts and exit")
	notifCmd.Flags().String("db", "", "Path to notification database (auto-detected if omitted)")
	notifCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	notifCmd.Flags().Bool("raw", false, "Dump raw bplist for each record")
	viper.BindPFlag("notif.app", notifCmd.Flags().Lookup("app"))
	viper.BindPFlag("notif.apps", notifCmd.Flags().Lookup("apps"))
	viper.BindPFlag("notif.db", notifCmd.Flags().Lookup("db"))
	viper.BindPFlag("notif.json", notifCmd.Flags().Lookup("json"))
	viper.BindPFlag("notif.raw", notifCmd.Flags().Lookup("raw"))
}

// notifCmd reads the macOS Notification Center SQLite store.
var notifCmd = &cobra.Command{
	Use:           "notif",
	Short:         "🚧 Read macOS Notification Center database",
	Args:          cobra.NoArgs,
	Hidden:        true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		dbPath := viper.GetString("notif.db")
		bundleID := viper.GetString("notif.app")
		listApps := viper.GetBool("notif.apps")
		asJSON := viper.GetBool("notif.json")
		raw := viper.GetBool("notif.raw")

		db, err := notif.Open(dbPath)
		if err != nil {
			return err
		}
		defer db.Close()

		if listApps {
			apps, err := notif.Apps(db)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(apps)
			}
			for _, id := range slices.Sorted(maps.Keys(apps)) {
				if apps[id] > 0 {
					fmt.Printf("%5d  %s\n", apps[id], id)
				}
			}
			return nil
		}

		recs, err := notif.List(db, bundleID)
		if err != nil {
			return err
		}

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(recs)
		}

		titleC := color.New(color.Bold, color.FgHiBlue).SprintFunc()
		bundleC := color.New(color.FgHiCyan).SprintFunc()
		dim := color.New(color.Faint).SprintFunc()

		for _, r := range recs {
			if r.Delivered.IsZero() {
				fmt.Printf("%s  %s\n", dim("(scheduled)        "), bundleC(r.BundleID))
			} else {
				fmt.Printf("%s  %s\n", dim(r.Delivered.Local().Format("2006-01-02 15:04:05")), bundleC(r.BundleID))
			}
			if r.Title != "" {
				fmt.Printf("  %s\n", titleC(r.Title))
			}
			if r.Subtitle != "" {
				fmt.Printf("  %s\n", r.Subtitle)
			}
			if r.Body != "" {
				for line := range strings.SplitSeq(r.Body, "\n") {
					fmt.Printf("  %s\n", line)
				}
			}
			if raw {
				if v, err := notif.DumpRaw(r.Raw); err == nil {
					b, _ := json.MarshalIndent(v, "  ", "  ")
					fmt.Printf("  %s\n", string(b))
				}
			}
			fmt.Println()
		}
		log.Infof("Found %d notification record(s)", len(recs))
		return nil
	},
}
