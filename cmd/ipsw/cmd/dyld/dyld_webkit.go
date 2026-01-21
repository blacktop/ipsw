/*
Copyright © 2018-2025 blacktop

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
package dyld

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
	dcsCmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	semver "github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(WebkitCmd)
	WebkitCmd.Flags().BoolP("rev", "r", false, "Lookup svn rev on trac.webkit.org")
	WebkitCmd.Flags().BoolP("git", "g", false, "Lookup git tag on github.com")
	WebkitCmd.Flags().StringP("api", "a", "", "Github API Token")
	WebkitCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	WebkitCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	WebkitCmd.Flags().BoolP("diff", "d", false, "Diff two dyld_shared_cache files")
	WebkitCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	viper.BindPFlag("dyld.webkit.rev", WebkitCmd.Flags().Lookup("rev"))
	viper.BindPFlag("dyld.webkit.git", WebkitCmd.Flags().Lookup("git"))
	viper.BindPFlag("dyld.webkit.api", WebkitCmd.Flags().Lookup("api"))
	viper.BindPFlag("dyld.webkit.proxy", WebkitCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("dyld.webkit.insecure", WebkitCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("dyld.webkit.diff", WebkitCmd.Flags().Lookup("diff"))
	viper.BindPFlag("dyld.webkit.json", WebkitCmd.Flags().Lookup("json"))
}

// WebkitCmd represents the webkit command
var WebkitCmd = &cobra.Command{
	Use:     "webkit <DSC>",
	Aliases: []string{"w"},
	Short:   "Get WebKit version from a dyld_shared_cache",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		getRev := viper.GetBool("dyld.webkit.rev")
		getGit := viper.GetBool("dyld.webkit.git")
		proxy := viper.GetString("dyld.webkit.proxy")
		insecure := viper.GetBool("dyld.webkit.insecure")
		apiToken := viper.GetString("dyld.webkit.api")
		diff := viper.GetBool("dyld.webkit.diff")
		asJSON := viper.GetBool("dyld.webkit.json")

		if len(apiToken) == 0 {
			if val, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
				apiToken = val
			} else {
				if val, ok := os.LookupEnv("GITHUB_API_TOKEN"); ok {
					apiToken = val
				}
			}
		}

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		webkit1, err := dcsCmd.GetWebkitVersion(f)
		if err != nil {
			return fmt.Errorf("failed to get WebKit version: %v", err)
		}

		if diff {
			dscPath2 := filepath.Clean(args[1])
			fileInfo, err := os.Lstat(dscPath2)
			if err != nil {
				return fmt.Errorf("file %s does not exist", dscPath2)
			}
			// Check if file is a symlink
			if fileInfo.Mode()&os.ModeSymlink != 0 {
				symlinkPath, err := os.Readlink(dscPath2)
				if err != nil {
					return errors.Wrapf(err, "failed to read symlink %s", dscPath2)
				}
				// TODO: this seems like it would break
				linkParent := filepath.Dir(dscPath2)
				linkRoot := filepath.Dir(linkParent)

				dscPath2 = filepath.Join(linkRoot, symlinkPath)
			}

			f, err := dyld.Open(dscPath2)
			if err != nil {
				return err
			}
			defer f.Close()

			webkit2, err := dcsCmd.GetWebkitVersion(f)
			if err != nil {
				return fmt.Errorf("failed to get WebKit version: %v", err)
			}

			out, err := utils.GitDiff(
				webkit1+"\n",
				webkit2+"\n",
				&utils.GitDiffConfig{
					Color: colors.Active(),
					Tool: viper.GetString("diff-tool"),
				})
			if err != nil {
				return err
			}
			if len(out) == 0 {
				log.Info("No differences found")
				return nil
			}
			log.Info("Differences found")
			fmt.Println(out)

			return nil
		}

		var svnRev string
		if getRev {
			log.Info("Querying https://trac.webkit.org...")
			ver, rev, err := dyld.ScrapeWebKitTRAC(webkit1)
			if err != nil {
				log.Infof("WebKit Version: %s", webkit1)
				return err
			}
			svnRev = fmt.Sprintf("%s (svn rev %s)", ver, rev)
		} else if getGit {
			log.Infof("WebKit Version: %s", webkit1)
			log.Info("Querying https://github.com API...")
			var tags []download.GithubTag
			if len(apiToken) == 0 {
				tags, err = download.GetPreprocessedWebKitTags(proxy, insecure)
				if err != nil {
					log.Infof("WebKit Version: %s", webkit1)
					return err
				}
			} else {
				tags, err = download.WebKitGraphQLTags(proxy, insecure, apiToken)
				if err != nil {
					log.Infof("WebKit Version: %s", webkit1)
					return err
				}
			}
			wkver, err := semver.NewVersion(webkit1)
			if err != nil {
				return fmt.Errorf("failed to parse WebKit version %s: %v", webkit1, err)
			}
			// search
			exact := false
			var match download.GithubTag
			for _, tag := range tags {
				if !strings.HasPrefix(tag.Name, "WebKit-7") {
					continue
				}
				tver, err := semver.NewVersion(strings.TrimPrefix(tag.Name, "WebKit-7"))
				if err != nil {
					continue
				}
				if wkver.Equal(tver) {
					exact = true
					match = tag
					break
				} else if wkver.GreaterThan(tver) {
					match = tag
					break
				}
			}
			// output
			if asJSON {
				b, err := json.Marshal(&struct {
					Version string             `json:"version"`
					Tag     download.GithubTag `json:"tag"`
					Exact   bool               `json:"exact"`
				}{
					Version: webkit1,
					Tag:     match,
					Exact:   exact,
				})
				if err != nil {
					return err
				}
				fmt.Println(string(b))
			} else {
				log.Infof("WebKit Version: %s", webkit1)
				if !exact {
					log.Warn("No exact match found (using closest match)")
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Tag:  %s", match.Name))
				utils.Indent(log.Info, 2)(fmt.Sprintf("URL:  %s", match.TarURL))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Date: %s", match.Commit.Date.Format("02Jan2006 15:04:05")))
			}
			return nil
		}

		if asJSON {
			b, err := json.Marshal(&struct {
				Version string `json:"version"`
				Rev     string `json:"rev,omitempty"`
			}{
				Version: webkit1,
				Rev:     svnRev,
			})
			if err != nil {
				return err
			}
			fmt.Println(string(b))
		} else {
			log.Infof("WebKit Version: %s", webkit1)
			if len(svnRev) > 0 {
				utils.Indent(log.Info, 2)(svnRev)
			}
		}

		return nil
	},
}
