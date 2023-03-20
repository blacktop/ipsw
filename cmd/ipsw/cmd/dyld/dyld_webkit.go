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
package dyld

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
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
	WebkitCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// WebkitCmd represents the webkit command
var WebkitCmd = &cobra.Command{
	Use:     "webkit <dyld_shared_cache>",
	Aliases: []string{"w"},
	Short:   "Get WebKit version from a dyld_shared_cache",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		getRev, _ := cmd.Flags().GetBool("rev")
		getGit, _ := cmd.Flags().GetBool("git")
		proxy, _ := cmd.Flags().GetString("proxy")
		insecure, _ := cmd.Flags().GetBool("insecure")
		apiToken, _ := cmd.Flags().GetString("api")
		diff, _ := cmd.Flags().GetBool("diff")
		asJSON, _ := cmd.Flags().GetBool("json")

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

		image, err := f.Image("WebKit")
		if err != nil {
			return fmt.Errorf("image not in %s: %v", dscPath, err)
		}

		m, err := image.GetPartialMacho()
		if err != nil {
			return err
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

			image, err := f.Image("WebKit")
			if err != nil {
				return fmt.Errorf("image not in %s: %v", dscPath2, err)
			}

			m2, err := image.GetPartialMacho()
			if err != nil {
				return err
			}

			out, err := utils.GitDiff(
				m.SourceVersion().Version.String()+"\n",
				m2.SourceVersion().Version.String()+"\n",
				&utils.GitDiffConfig{Color: viper.GetBool("color"), Tool: viper.GetString("diff-tool")})
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
			ver, rev, err := dyld.ScrapeWebKitTRAC(m.SourceVersion().Version.String())
			if err != nil {
				log.Infof("WebKit Version: %s", m.SourceVersion().Version)
				return err
			}
			svnRev = fmt.Sprintf("%s (svn rev %s)", ver, rev)
		} else if getGit {
			log.Info("Querying https://github.com API...")
			var tags []download.GithubTag
			if len(apiToken) == 0 {
				tags, err = download.GetPreprocessedWebKitTags(proxy, insecure)
				if err != nil {
					log.Infof("WebKit Version: %s", m.SourceVersion().Version)
					return err
				}
			} else {
				tags, err = download.WebKitGraphQLTags(proxy, insecure, apiToken)
				if err != nil {
					log.Infof("WebKit Version: %s", m.SourceVersion().Version)
					return err
				}
			}
			for _, tag := range tags {
				if strings.Contains(tag.Name, m.SourceVersion().Version.String()) {
					if asJSON {
						b, err := json.Marshal(&struct {
							Version string             `json:"version"`
							Tag     download.GithubTag `json:"tag,omitempty"`
						}{
							Version: m.SourceVersion().Version.String(),
							Tag:     tag,
						})
						if err != nil {
							return err
						}
						fmt.Println(string(b))
					} else {
						log.Infof("WebKit Version: %s", m.SourceVersion().Version)
						utils.Indent(log.Info, 2)(fmt.Sprintf("Tag:  %s", tag.Name))
						utils.Indent(log.Info, 2)(fmt.Sprintf("URL:  %s", tag.TarURL))
						utils.Indent(log.Info, 2)(fmt.Sprintf("Date: %s", tag.Commit.Date.Format("02Jan2006 15:04:05")))
					}
					return nil
				}
			}
		}

		if asJSON {
			b, err := json.Marshal(&struct {
				Version string `json:"version"`
				Rev     string `json:"rev,omitempty"`
			}{
				Version: m.SourceVersion().Version.String(),
				Rev:     svnRev,
			})
			if err != nil {
				return err
			}
			fmt.Println(string(b))
		} else {
			log.Infof("WebKit Version: %s", m.SourceVersion().Version)
			if len(svnRev) > 0 {
				utils.Indent(log.Info, 2)(svnRev)
			}
		}

		return nil
	},
}
