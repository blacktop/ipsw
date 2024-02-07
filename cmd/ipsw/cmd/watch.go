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
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/watch"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var colorHeader = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorHighlight = color.New(color.Bold, color.BgHiYellow).SprintfFunc()
var colorSeparator = color.New(color.Faint).SprintFunc()

func highlightHeader(re *regexp.Regexp, input string) string {
	parts := re.FindAllStringIndex(input, -1)
	if len(parts) == 0 {
		return colorHeader(input)
	}
	highlighted := ""
	lastIndex := 0
	for _, part := range parts {
		highlighted += colorHeader(input[lastIndex:part[0]])
		highlighted += colorHighlight(input[part[0]:part[1]])
		lastIndex = part[1]
	}
	highlighted += colorHeader(input[lastIndex:])
	return highlighted
}

func init() {
	rootCmd.AddCommand(watchCmd)

	watchCmd.Flags().StringP("branch", "b", "main", "Repo branch to watch")
	watchCmd.Flags().StringP("file", "f", "", "Commit file path to watch")
	watchCmd.Flags().StringP("pattern", "p", "", "Commit message pattern to match")
	watchCmd.Flags().IntP("days", "d", 1, "Days back to search for commits")
	watchCmd.Flags().StringP("api", "a", "", "Github API Token")
	watchCmd.Flags().Bool("json", false, "Output downloadable tar.gz URLs as JSON")
	watchCmd.Flags().DurationP("timeout", "t", 0, "Timeout for watch attempts (default: 0s = no timeout/run once)")
	watchCmd.Flags().String("discord-id", "", "Discord Webhook ID")
	watchCmd.Flags().String("discord-token", "", "Discord Webhook Token")
	viper.BindPFlag("watch.branch", watchCmd.Flags().Lookup("branch"))
	viper.BindPFlag("watch.file", watchCmd.Flags().Lookup("file"))
	viper.BindPFlag("watch.pattern", watchCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("watch.days", watchCmd.Flags().Lookup("days"))
	viper.BindPFlag("watch.api", watchCmd.Flags().Lookup("api"))
	viper.BindPFlag("watch.json", watchCmd.Flags().Lookup("json"))
	viper.BindPFlag("watch.timeout", watchCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("watch.discord-id", watchCmd.Flags().Lookup("discord-id"))
	viper.BindPFlag("watch.discord-token", watchCmd.Flags().Lookup("discord-token"))
}

// TODO: add support for watching local repos so that we can leverage `git log -L :func:file` to watch a single function

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:           "watch <ORG/REPO>",
	Short:         "Watch Github Commits",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		apiToken := viper.GetString("watch.api")
		asJSON := viper.GetBool("watch.json")
		annouce := false

		if viper.GetString("watch.discord-id") != "" && viper.GetString("watch.discord-token") != "" {
			annouce = true
		}

		if len(apiToken) == 0 {
			if val, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
				apiToken = val
			} else {
				if val, ok := os.LookupEnv("GITHUB_API_TOKEN"); ok {
					apiToken = val
				}
			}
		}

		parts := strings.Split(args[0], "/")
		if len(parts) != 2 {
			return fmt.Errorf("invalid repo: %s (should be in the form 'org/repo')", args[0])
		}

		seenCommitOIDs := make(map[string]bool) // TODO: this can grow unbounded, need to limit it or switch to a LRU cache

		shouldStop := false

		if time.Duration(viper.GetDuration("watch.timeout")) == 0 {
			shouldStop = true
		}

		for {
			commits, err := download.GetGithubCommits(
				parts[0], // org
				parts[1], // repo
				viper.GetString("watch.branch"),
				viper.GetString("watch.file"),
				viper.GetString("watch.pattern"),
				viper.GetInt("watch.days"),
				"",
				false,
				apiToken)
			if err != nil {
				return err
			}

			if annouce {
				for _, commit := range commits {
					if err := watch.DiscordAnnounce(string(commit.Message), &watch.Config{
						DiscordWebhookID:    viper.GetString("watch.discord-id"),
						DiscordWebhookToken: viper.GetString("watch.discord-token"),
						DiscordColor:        "4535172",
						DiscordAuthor:       string(commit.Author.Name),
						DiscordIconURL:      "https://raw.githubusercontent.com/blacktop/ipsw/master/www/static/img/webkit.png",
					}); err != nil {
						return fmt.Errorf("discord announce failed: %v", err)
					}
				}
			} else if asJSON {
				for _, commit := range commits {
					if _, ok := seenCommitOIDs[string(commit.OID)]; !ok {
						seenCommitOIDs[string(commit.OID)] = true
					} else {
						continue
					}
					json.NewEncoder(os.Stdout).Encode(commit)
				}
			} else {
				for idx, commit := range commits {
					// check if we've seen this commit before and skip if we have
					if _, ok := seenCommitOIDs[string(commit.OID)]; !ok {
						seenCommitOIDs[string(commit.OID)] = true
					} else {
						continue
					}
					re := regexp.MustCompile(viper.GetString("watch.pattern"))
					fmt.Println(highlightHeader(re, string(commit.MsgHeadline)))
					fmt.Printf("\n%s\n\n", colorSeparator(
						fmt.Sprintf("commit: %s (author: %s, date: %s)",
							commit.OID,
							commit.Author.Name,
							commit.Author.Date.Format("02Jan2006 15:04:05")),
					))
					body := re.ReplaceAllStringFunc(string(commit.MsgBody), func(s string) string {
						return colorHighlight(s)
					})
					fmt.Println(body)
					if idx < len(commits)-1 {
						println()
						fmt.Println(colorSeparator("---"))
						println()
					}
				}
			}

			if shouldStop { // if timeout is 0 then just run once
				break
			}

			// sleep for timeout
			time.Sleep(time.Duration(viper.GetDuration("watch.timeout")))
		}

		return nil
	},
}
