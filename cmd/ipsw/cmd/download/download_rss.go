/*
Copyright © 2018-2023 blacktop

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
package download

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/gen2brain/beeep"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(rssCmd)

	rssCmd.Flags().BoolP("watch", "w", false, "Watch for NEW releases")
	rssCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	rssCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("device")
		DownloadCmd.PersistentFlags().MarkHidden("model")
		DownloadCmd.PersistentFlags().MarkHidden("version")
		DownloadCmd.PersistentFlags().MarkHidden("build")
		DownloadCmd.PersistentFlags().MarkHidden("confirm")
		DownloadCmd.PersistentFlags().MarkHidden("skip-all")
		DownloadCmd.PersistentFlags().MarkHidden("resume-all")
		DownloadCmd.PersistentFlags().MarkHidden("restart-all")
		DownloadCmd.PersistentFlags().MarkHidden("remove-commas")
		c.Parent().HelpFunc()(c, s)
	})
	viper.BindPFlag("download.rss.watch", rssCmd.Flags().Lookup("watch"))
	viper.BindPFlag("download.rss.json", rssCmd.Flags().Lookup("json"))
}

// rssCmd represents the rss command
var rssCmd = &cobra.Command{
	Use:     "rss",
	Aliases: []string{"r"},
	Short:   "Read Releases - Apple Developer RSS Feed",
	Run: func(cmd *cobra.Command, args []string) {
		var releases []string

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		watch := viper.GetBool("download.rss.watch")
		asJSON := viper.GetBool("download.rss.json")

		rss, err := download.GetRSS()
		if err != nil {
			log.Fatal(err.Error())
		}
		for _, item := range rss.Channel.Items {
			releases = append(releases, fmt.Sprintf("%s - %s", item.Title, item.PubDate))
		}

		if watch {
			log.Info("Watching Releases - Apple Developer RSS Feed...")
			for {
				time.Sleep(5 * time.Minute)

				// check for NEW releases
				rss, err := download.GetRSS()
				if err != nil {
					log.Fatal(err.Error())
				}

				for _, item := range rss.Channel.Items {
					if !utils.StrSliceHas(releases, fmt.Sprintf("%s - %s", item.Title, item.PubDate)) {

						releases = append(releases, fmt.Sprintf("%s - %s", item.Title, item.PubDate))

						if err := beeep.Alert("🆕 Apple - Release", fmt.Sprintf("%s - %s", item.Title, item.PubDate), "assets/warning.png"); err != nil {
							log.Fatal(err.Error())
						}
					}
				}
			}
		}

		if asJSON {
			rssJSON, err := json.Marshal(rss)
			if err != nil {
				log.Fatal(err.Error())
			}
			fmt.Println(string(rssJSON))
		} else {
			// Dump the Feed
			fmt.Printf("# %s (%s)\n\n", rss.Channel.Title, rss.Channel.Link)
			fmt.Printf("> %s  \n\n---\n\n", rss.Channel.Desc)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, item := range rss.Channel.Items {
				date, err := item.PubDate.GetDate()
				if err != nil {
					log.Fatal(err.Error())
				}
				fmt.Fprintf(w, "- %s\t<%s>\t%s  \n", item.Title, date.Format("Mon, 02Jan2006 15:04:05 MST"), item.Link)
			}
			w.Flush()
			fmt.Println()
		}
	},
}
