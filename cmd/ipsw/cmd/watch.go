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

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/watch"
	"github.com/blacktop/ipsw/internal/commands/watch/announce"
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

	watchCmd.Flags().BoolP("tags", "g", false, "Watch for new tags")
	watchCmd.Flags().StringP("branch", "b", "main", "Repo branch to watch")
	watchCmd.Flags().StringP("file", "f", "", "Commit file path to watch")
	watchCmd.Flags().StringP("pattern", "p", "", "Commit message pattern to match")
	watchCmd.Flags().IntP("days", "d", 1, "Days back to search for commits")
	watchCmd.Flags().StringP("api", "a", "", "Github API Token")
	watchCmd.Flags().Bool("json", false, "Output downloadable tar.gz URLs as JSON")
	watchCmd.Flags().DurationP("timeout", "t", 0, "Timeout for watch attempts (default: 0s = no timeout/run once)")
	watchCmd.Flags().StringP("command", "c", "", "Command to run on new commit")
	watchCmd.Flags().Bool("post", false, "Create social media post for NEW tags")
	watchCmd.Flags().Bool("discord", false, "Annouce to Discord")
	watchCmd.Flags().String("discord-id", "", "Discord Webhook ID")
	watchCmd.Flags().String("discord-token", "", "Discord Webhook Token")
	watchCmd.Flags().String("discord-icon", "", "Discord Post Icon URL")
	watchCmd.Flags().Bool("mastodon", false, "Annouce to Mastodon")
	watchCmd.Flags().String("mastodon-server", "https://mastodon.social", "Mastodon Server URL")
	watchCmd.Flags().String("mastodon-client-id", "", "Mastodon Client ID")
	watchCmd.Flags().String("mastodon-client-secret", "", "Mastodon Client Secret")
	watchCmd.Flags().String("mastodon-access-token", "", "Mastodon Access Token")
	watchCmd.Flags().String("cache", "", "Cache file to store seen commits/tags")
	viper.BindPFlag("watch.tags", watchCmd.Flags().Lookup("tags"))
	viper.BindPFlag("watch.branch", watchCmd.Flags().Lookup("branch"))
	viper.BindPFlag("watch.file", watchCmd.Flags().Lookup("file"))
	viper.BindPFlag("watch.pattern", watchCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("watch.days", watchCmd.Flags().Lookup("days"))
	viper.BindPFlag("watch.api", watchCmd.Flags().Lookup("api"))
	viper.BindPFlag("watch.json", watchCmd.Flags().Lookup("json"))
	viper.BindPFlag("watch.timeout", watchCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("watch.command", watchCmd.Flags().Lookup("command"))
	viper.BindPFlag("watch.post", watchCmd.Flags().Lookup("post"))
	viper.BindPFlag("watch.discord", watchCmd.Flags().Lookup("discord"))
	viper.BindPFlag("watch.discord-id", watchCmd.Flags().Lookup("discord-id"))
	viper.BindPFlag("watch.discord-token", watchCmd.Flags().Lookup("discord-token"))
	viper.BindPFlag("watch.discord-icon", watchCmd.Flags().Lookup("discord-icon"))
	viper.BindPFlag("watch.mastodon", watchCmd.Flags().Lookup("mastodon"))
	viper.BindPFlag("watch.mastodon-server", watchCmd.Flags().Lookup("mastodon-server"))
	viper.BindPFlag("watch.mastodon-client-id", watchCmd.Flags().Lookup("mastodon-client-id"))
	viper.BindPFlag("watch.mastodon-client-secret", watchCmd.Flags().Lookup("mastodon-client-secret"))
	viper.BindPFlag("watch.mastodon-access-token", watchCmd.Flags().Lookup("mastodon-access-token"))
	viper.BindPFlag("watch.cache", watchCmd.Flags().Lookup("cache"))
}

// TODO: add support for watching local repos so that we can leverage `git log -L :func:file` to watch a single function

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch <ORG/REPO>",
	Short: "Watch Github Commits",
	Example: heredoc.Doc(`
		# Watch the main branch of the WebKit/WebKit repo for new commits every 5 minutes with the pattern '254930' for the last 30 days
		❯ ipsw watch --pattern '254930' --days 30 WebKit/WebKit --branch main --timeout 5m
		# Watch the main branch of the WebKit/WebKit repo for new commits every 5 minutes and announce to Discord
		❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch --pattern 'Lockdown Mode' --days 1 --timeout 5m WebKit/WebKit
		# Watch the main branch of the WebKit/WebKit repo for new commits every 5 minutes and run a command on new commits
		# NOTE: the command will have access to the following environment variables:
		#   - IPSW_WATCH_OID
		#   - IPSW_WATCH_URL
		#   - IPSW_WATCH_AUTHOR
		#   - IPSW_WATCH_DATE
		#   - IPSW_WATCH_MESSAGE
		❯ ipsw watch WebKit/WebKit --command 'echo "New Commit: $IPSW_WATCH_URL"'
		# Watch WebKit/WebKit for new tags every 5 minutes and announce to Discord
		❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch WebKit/WebKit --tags --timeout 5m`),
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var cache watch.WatchCache

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		apiToken := viper.GetString("watch.api")
		asJSON := viper.GetBool("watch.json")
		postCommand := viper.GetString("watch.command")
		discord := viper.GetBool("watch.discord")
		mastodon := viper.GetBool("watch.mastodon")
		// validate flags
		if viper.GetBool("watch.tags") {
			if viper.IsSet("watch.branch") {
				return fmt.Errorf("--tags watching is not supported with --branch")
			}
			if viper.IsSet("watch.file") {
				return fmt.Errorf("--tags watching is not supported with --file")
			}
			if viper.IsSet("watch.pattern") {
				return fmt.Errorf("--tags watching is not supported with --pattern")
			}
			if viper.IsSet("watch.days") {
				return fmt.Errorf("--tags watching is not supported with --days")
			}
			if viper.IsSet("watch.json") {
				return fmt.Errorf("--tags watching is not supported with --json")
			}
			if viper.IsSet("watch.command") {
				return fmt.Errorf("--tags watching is not supported with --command")
			}
		} else {
			if viper.IsSet("watch.post") {
				return fmt.Errorf("commit watching is not supported with --post")
			}
		}
		if discord {
			if !viper.IsSet("watch.discord-id") || !viper.IsSet("watch.discord-token") {
				return fmt.Errorf("--discord announce requires --discord-id and --discord-token")
			}
		}
		if mastodon {
			if !viper.IsSet("watch.mastodon-client-id") || !viper.IsSet("watch.mastodon-client-secret") || !viper.IsSet("watch.mastodon-access-token") {
				return fmt.Errorf("--mastodon announce requires --mastodon-client-id, --mastodon-client-secret, and --mastodon-access-token")
			}
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

		if viper.IsSet("watch.cache") {
			cache, err = watch.NewFileCache(viper.GetString("watch.cache"))
			if err != nil {
				return err
			}
		} else {
			cache, err = watch.NewMemoryCache(100)
			if err != nil {
				return err
			}
		}

		parts := strings.Split(args[0], "/")
		if len(parts) != 2 {
			return fmt.Errorf("invalid repo: %s (should be in the form 'org/repo')", args[0])
		}

		shouldStop := false

		if time.Duration(viper.GetDuration("watch.timeout")) == 0 {
			shouldStop = true
		}

		for {
			if viper.GetBool("watch.tags") {
				var post string

				tags, err := download.GetLatestTagsV2(parts[0], parts[1], 2, "", false, apiToken)
				if err != nil {
					return fmt.Errorf("failed to get %s tags: %v", args[0], err)
				}
				if _, ok := cache.Get(tags[0]); !ok {
					cache.Add(tags[0], tags[1])

					if viper.GetBool("watch.post") {
						post, err = watch.Post(tags[1], tags[0])
						if err != nil {
							return err
						}
					}

					if discord || mastodon {
						if discord {
							iconURL := viper.GetString("watch.discord-icon")
							if iconURL == "" {
								iconURL = "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"
							}
							if post == "" {
								post = fmt.Sprintf("%s/%s\n\t - [%s](https://github.com/%s/%s/releases/tag/%s)", parts[0], parts[1], tags[0], parts[0], parts[1], tags[0])
							}
							if err := announce.Discord(post, &announce.DiscordConfig{
								DiscordWebhookID:    viper.GetString("watch.discord-id"),
								DiscordWebhookToken: viper.GetString("watch.discord-token"),
								DiscordColor:        "4535172",
								DiscordAuthor:       "🆕 TAG",
								DiscordIconURL:      iconURL,
							}); err != nil {
								return fmt.Errorf("discord announce failed: %v", err)
							}
						}
						if mastodon {
							if post == "" {
								post = fmt.Sprintf("%s/%s\n\t - [%s](https://github.com/%s/%s/releases/tag/%s)", parts[0], parts[1], tags[0], parts[0], parts[1], tags[0])
							}
							if err := announce.Mastodon(post, &announce.MastodonConfig{
								Server:       viper.GetString("watch.mastodon-server"),
								ClientID:     viper.GetString("watch.mastodon-client-id"),
								ClientSecret: viper.GetString("watch.mastodon-client-secret"),
								AccessToken:  viper.GetString("watch.mastodon-access-token"),
							}); err != nil {
								return fmt.Errorf("mastodon announce failed: %v", err)
							}
						}
					} else {
						if post == "" {
							fmt.Println(tags[0])
						} else {
							fmt.Println(post)
						}
					}
				}
			} else {
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
					return fmt.Errorf("failed to get %s commits: %v", args[0], err)
				}

				for idx, commit := range commits {
					if _, ok := cache.Get(string(commit.OID)); !ok {
						cache.Add(string(commit.OID), commit)

						if discord || mastodon {
							if discord && !viper.IsSet("watch.command") {
								iconURL := viper.GetString("watch.discord-icon")
								if iconURL == "" {
									iconURL = "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"
								}
								if err := announce.Discord(string(commit.Message), &announce.DiscordConfig{
									DiscordWebhookID:    viper.GetString("watch.discord-id"),
									DiscordWebhookToken: viper.GetString("watch.discord-token"),
									DiscordColor:        "4535172",
									DiscordAuthor:       string(commit.Author.Name),
									DiscordIconURL:      iconURL,
								}); err != nil {
									return fmt.Errorf("discord announce failed: %v", err)
								}
							}
							if mastodon && !viper.IsSet("watch.command") {
								if err := announce.Mastodon(string(commit.Message), &announce.MastodonConfig{
									Server:       viper.GetString("watch.mastodon-server"),
									ClientID:     viper.GetString("watch.mastodon-client-id"),
									ClientSecret: viper.GetString("watch.mastodon-client-secret"),
									AccessToken:  viper.GetString("watch.mastodon-access-token"),
								}); err != nil {
									return fmt.Errorf("mastodon announce failed: %v", err)
								}
							}
						} else if asJSON {
							json.NewEncoder(os.Stdout).Encode(commit)
						} else if postCommand != "" {
							if err := watch.RunCommand(postCommand, commit); err != nil {
								return fmt.Errorf("post command failed: %v", err)
							}
						} else {
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
