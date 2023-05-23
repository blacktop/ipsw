/*
Copyright © 2023 blacktop

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

	"github.com/apex/log"
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

	watchCmd.Flags().StringP("file", "f", "", "Commit file path to watch")
	watchCmd.Flags().StringP("pattern", "p", "", "Commit message pattern to match")
	watchCmd.Flags().IntP("days", "d", 1, "Days back to search for commits")
	watchCmd.Flags().StringP("api", "a", "", "Github API Token")
	watchCmd.Flags().Bool("json", false, "Output downloadable tar.gz URLs as JSON")
	viper.BindPFlag("watch.file", watchCmd.Flags().Lookup("file"))
	viper.BindPFlag("watch.pattern", watchCmd.Flags().Lookup("pattern"))
	viper.BindPFlag("watch.days", watchCmd.Flags().Lookup("days"))
	viper.BindPFlag("watch.api", watchCmd.Flags().Lookup("api"))
	viper.BindPFlag("watch.json", watchCmd.Flags().Lookup("json"))
}

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:           "watch",
	Short:         "Watch WebKit Commits",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		apiToken := viper.GetString("watch.api")
		asJSON := viper.GetBool("watch.json")

		if len(apiToken) == 0 {
			if val, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
				apiToken = val
			} else {
				if val, ok := os.LookupEnv("GITHUB_API_TOKEN"); ok {
					apiToken = val
				}
			}
		}

		commits, err := download.WebKitCommits(
			viper.GetString("watch.file"),
			viper.GetString("watch.pattern"),
			viper.GetInt("watch.days"),
			"",
			false,
			apiToken)
		if err != nil {
			return err
		}

		if asJSON {
			json.NewEncoder(os.Stdout).Encode(commits)
		} else {
			for _, commit := range commits {
				re := regexp.MustCompile(viper.GetString("watch.pattern"))
				fmt.Println(highlightHeader(re, string(commit.Headline)))
				println()
				println(colorSeparator("commit: " + commit.OID))
				println()
				body := re.ReplaceAllStringFunc(string(commit.Body), func(s string) string {
					return colorHighlight(s)
				})
				fmt.Println(body)
				println()
				fmt.Println(colorSeparator("---"))
				println()
			}
		}

		return nil
	},
}
