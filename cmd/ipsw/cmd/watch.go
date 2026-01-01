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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/commands/watch"
	"github.com/blacktop/ipsw/internal/commands/watch/announce"
	watchgit "github.com/blacktop/ipsw/internal/commands/watch/git"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var colorHeader = colors.BoldHiBlue().SprintFunc()
var colorHighlight = colors.BoldOnHiYellow().SprintfFunc()
var colorSeparator = colors.Faint().SprintFunc()

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
	watchCmd.Flags().StringP("func", "", "", "Function name to watch (for local repos)")
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
	watchCmd.Flags().String("ssh-key", "", "SSH private key for git operations")
	viper.BindPFlag("watch.tags", watchCmd.Flags().Lookup("tags"))
	viper.BindPFlag("watch.branch", watchCmd.Flags().Lookup("branch"))
	viper.BindPFlag("watch.file", watchCmd.Flags().Lookup("file"))
	viper.BindPFlag("watch.func", watchCmd.Flags().Lookup("func"))
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
	viper.BindPFlag("watch.ssh-key", watchCmd.Flags().Lookup("ssh-key"))
}

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
		❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch WebKit/WebKit --tags --timeout 5m
		# Watch a specific function in a local repo
		❯ ipsw watch /path/to/local/REPO --func "MyFunction" --file "path/to/file.go" --timeout 5m`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var cache watch.WatchCache
		// flags
		funcName := viper.GetString("watch.func")
		filePath := viper.GetString("watch.file")
		apiToken := viper.GetString("watch.api")
		asJSON := viper.GetBool("watch.json")
		postCommand := viper.GetString("watch.command")
		discord := viper.GetBool("watch.discord")
		mastodon := viper.GetBool("watch.mastodon")
		// validate flags
		if viper.GetBool("watch.tags") {
			if cmd.Flags().Changed("branch") {
				return fmt.Errorf("--tags watching is not supported with --branch")
			}
			if viper.GetString("watch.file") != "" {
				return fmt.Errorf("--tags watching is not supported with --file")
			}
			if viper.GetString("watch.pattern") != "" {
				return fmt.Errorf("--tags watching is not supported with --pattern")
			}
			if cmd.Flags().Changed("days") {
				return fmt.Errorf("--tags watching is not supported with --days")
			}
			if viper.GetBool("watch.json") {
				return fmt.Errorf("--tags watching is not supported with --json")
			}
			if viper.GetString("watch.command") != "" {
				return fmt.Errorf("--tags watching is not supported with --command")
			}
			if viper.GetString("watch.func") != "" {
				return fmt.Errorf("--tags watching is not supported with --func")
			}
		} else {
			if viper.GetBool("watch.post") {
				return fmt.Errorf("commit watching is not supported with --post")
			}
			if viper.GetString("watch.func") != "" && viper.GetString("watch.file") == "" {
				return fmt.Errorf("--func requires --file to be set")
			}
		}
		if discord {
			if viper.GetString("watch.discord-id") == "" || viper.GetString("watch.discord-token") == "" {
				return fmt.Errorf("--discord announce requires --discord-id and --discord-token")
			}
		}
		if mastodon {
			if viper.GetString("watch.mastodon-client-id") == "" || viper.GetString("watch.mastodon-client-secret") == "" || viper.GetString("watch.mastodon-access-token") == "" {
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

		if viper.GetString("watch.cache") != "" {
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

		if viper.GetString("watch.func") != "" {
			repoPath, err := filepath.Abs(args[0])
			if err != nil {
				return fmt.Errorf("failed to get absolute path for repository: %v", err)
			}
			if !filepath.IsAbs(filePath) {
				filePath = filepath.Join(repoPath, filePath)
			}
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("file does not exist: %s", filePath)
				}
				return fmt.Errorf("error accessing file: %v", err)
			}
			if fileInfo.IsDir() {
				return fmt.Errorf("path is a directory, not a file: %s", filePath)
			}
			relFilePath, err := filepath.Rel(repoPath, filePath)
			if err != nil {
				return fmt.Errorf("failed to get relative path: %v", err)
			}
			relFilePath = filepath.ToSlash(relFilePath)

			repo, err := git.PlainOpen(repoPath)
			if err != nil {
				return fmt.Errorf("failed to open git repository: %v", err)
			}

			shouldStop := false
			if time.Duration(viper.GetDuration("watch.timeout")) == 0 {
				shouldStop = true
			}

			log.WithFields(log.Fields{
				"func": funcName,
				"file": relFilePath,
			}).Infof("Watching Function")

			if _, err = repo.Head(); err != nil {
				return fmt.Errorf("repository appears to have no commits: %v", err)
			}

			for {
				allChanges, err := watchgit.GetFunctionChanges(repo, funcName, relFilePath)
				if err != nil {
					if shouldStop {
						return fmt.Errorf("failed to get function changes: %v", err)
					}
					log.Warnf("Failed to get function changes: %v", err)
					time.Sleep(time.Duration(viper.GetDuration("watch.timeout")))
					continue
				}

				if len(allChanges) == 0 {
					// function not found or no history, wait and try again
					if shouldStop {
						log.Infof("Function '%s' not found in '%s'. Stopping.", funcName, relFilePath)
						break // exit loop
					}
					log.WithFields(log.Fields{
						"func": funcName,
						"file": relFilePath,
					}).Debugf("Function NOT found, waiting...")
					time.Sleep(time.Duration(viper.GetDuration("watch.timeout")))
					continue
				}

				latestChange := allChanges[0] // Newest change is first
				latestCommitOID := string(latestChange.Commit.OID)

				// Cache key based on function and file
				cacheKey := fmt.Sprintf("%s:%s", funcName, relFilePath)
				cachedValue := cache.Get(repoPath)

				if cachedValue == nil || !slices.Contains(cachedValue.Commits, latestCommitOID) {
					if err := cache.Add(repoPath, watch.Function{
						cacheKey: latestCommitOID,
					}); err != nil {
						return fmt.Errorf("failed to add to latest function change commit %s to cache: %v", latestCommitOID, err)
					}

					// Prepare display output
					var displayOutput strings.Builder
					commit := latestChange.Commit
					fmt.Fprintf(&displayOutput, "commit %s\n", commit.OID)
					fmt.Fprintf(&displayOutput, "Author: %s <%s>\n", commit.Author.Name, commit.Author.Email)
					fmt.Fprintf(&displayOutput, "Date: %s\n\n", commit.Author.Date.Format("Mon Jan 2 15:04:05 2006 -0700"))
					fmt.Fprintf(&displayOutput, "    %s\n\n", commit.MsgHeadline)

					// Generate diff with previous version if available
					previousContent := ""
					if len(allChanges) > 1 {
						previousContent = allChanges[1].Content
					}

					if discord || mastodon || postCommand != "" {
						diff, err := utils.GitDiff(previousContent, latestChange.Content,
							&utils.GitDiffConfig{
								Color: false,
								Tool:  "git",
							})
						if err != nil {
							return err
						}
						fmt.Fprintf(&displayOutput, "```diff\n%s\n```\n", diff)

						notificationTitle := fmt.Sprintf("🆕 Change in %s:%s", relFilePath, funcName)
						notificationBody := displayOutput.String()
						if discord {
							iconURL := viper.GetString("watch.discord-icon")
							if iconURL == "" {
								iconURL = "https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png"
							}
							if len(notificationBody) > 1997 { // truncate to 1997 characters (discord limit is 2000)
								notificationBody = notificationBody[:1997] + "..."
							}
							if err := announce.Discord(notificationBody, &announce.DiscordConfig{
								DiscordWebhookID:    viper.GetString("watch.discord-id"),
								DiscordWebhookToken: viper.GetString("watch.discord-token"),
								DiscordColor:        "16776960", // Yellow for changes
								DiscordAuthor:       notificationTitle,
								DiscordIconURL:      iconURL,
							}); err != nil {
								log.WithError(err).Error("Discord announce failed")
							}
						}
						if mastodon {
							mastodonBody := notificationTitle + "\n" + notificationBody
							if len(mastodonBody) > 500 { // truncate to 500 characters (mastodon limit is 500)
								mastodonBody = mastodonBody[:497] + "..."
							}
							if err := announce.Mastodon(mastodonBody, &announce.MastodonConfig{
								Server:       viper.GetString("watch.mastodon-server"),
								ClientID:     viper.GetString("watch.mastodon-client-id"),
								ClientSecret: viper.GetString("watch.mastodon-client-secret"),
								AccessToken:  viper.GetString("watch.mastodon-access-token"),
							}); err != nil {
								log.WithError(err).Error("Mastodon announce failed")
							}
						}
						// run command if configured
						if postCommand != "" {
							if err := watch.RunCommand(postCommand, *commit); err != nil {
								log.Errorf("post command failed: %v", err)
							}
						}
					} else {
						diff, err := utils.GitDiff(previousContent, latestChange.Content,
							&utils.GitDiffConfig{
								Color: colors.Active(),
								Tool:  viper.GetString("diff-tool"),
							})
						if err != nil {
							return err
						}
						fmt.Fprintf(&displayOutput, "%s\n", diff)
						fmt.Println(displayOutput.String())
					}
				} // end if cache miss

				if shouldStop {
					break // exit loop
				}

				time.Sleep(time.Duration(viper.GetDuration("watch.timeout")))

				// refresh repo
				worktree, err := repo.Worktree()
				if err != nil {
					log.Warnf("Failed to get worktree: %v", err)
				} else {
					log.Debug("Pulling changes from remote")
					var auth transport.AuthMethod
					if sshKeyPath := viper.GetString("watch.ssh-key"); sshKeyPath != "" {
						// Use specified SSH key
						if key, err := os.ReadFile(sshKeyPath); err == nil {
							publicKeys, err := ssh.NewPublicKeys("git", key, "")
							if err != nil {
								log.Warnf("SSH key auth failed: %v", err)
							} else {
								auth = publicKeys
							}
						} else {
							log.Warnf("Failed to read SSH key: %v", err)
						}
					}
					if err := worktree.Pull(&git.PullOptions{
						RemoteName: "origin",
						Progress:   os.Stdout,
						Auth:       auth,
					}); err != nil && err != git.NoErrAlreadyUpToDate && err != git.ErrUnstagedChanges {
						log.Warnf("Failed to pull: %v", err)
					}
				}
			} // end for loop

			return nil
		}

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
				if !cache.Has(args[0], watch.Tags{tags[0]}) {
					if err := cache.Add(args[0], watch.Tags{tags[0], tags[1]}); err != nil {
						return fmt.Errorf("failed to add tags to cache: %v", err)
					}

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
					if !cache.Has(args[0], watch.Commits{string(commit.OID)}) {
						if err := cache.Add(args[0], watch.Commits{string(commit.OID)}); err != nil {
							return fmt.Errorf("failed to add commit %s to cache: %v", string(commit.OID), err)
						}

						if discord || mastodon {
							if discord && viper.GetString("watch.command") == "" {
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
							if mastodon && viper.GetString("watch.command") == "" {
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
