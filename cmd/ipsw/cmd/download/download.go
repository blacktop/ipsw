/*
Copyright © 2018-2026 blacktop

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
	"fmt"
	"path"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.PersistentFlags().Int("parts", download.DefaultParts,
		"maximum parallel connections per download")
	DownloadCmd.PersistentFlags().Int("min-parts", download.DefaultMinParts,
		"connections opened immediately and never retired by throughput measurement "+
			"(equal to --parts disables ramping)")
	viper.BindPFlag("download.parts", DownloadCmd.PersistentFlags().Lookup("parts"))
	viper.BindPFlag("download.min-parts", DownloadCmd.PersistentFlags().Lookup("min-parts"))
}

// ApplyConcurrency resolves the download.parts/download.min-parts config keys
// (flags, config file, or defaults) and installs the engine policy. The root
// hook calls it so engine consumers outside this command group (ipsw update,
// ipsw dtree --remote) honor the keys too.
func ApplyConcurrency() error {
	parts, err := configInt("download.parts")
	if err != nil {
		return err
	}
	minParts, err := configInt("download.min-parts")
	if err != nil {
		return err
	}
	// lowering --parts alone must not conflict with the untouched
	// min-parts default: clamp unless the user set min-parts explicitly
	if minParts > parts && !minPartsExplicit() {
		minParts = parts
	}
	return download.SetConcurrency(download.Concurrency{
		Parts:    parts,
		MinParts: minParts,
	})
}

func minPartsExplicit() bool {
	if f := DownloadCmd.PersistentFlags().Lookup("min-parts"); f != nil && f.Changed {
		return true
	}
	return viper.InConfig("download.min-parts")
}

func configInt(key string) (int, error) {
	value := viper.Get(key)
	if value == nil {
		// viper was reset (tests) or the binding is gone: the flag still
		// carries the compiled default
		if f := DownloadCmd.PersistentFlags().Lookup(strings.TrimPrefix(key, "download.")); f != nil {
			value = f.Value.String()
		}
	}
	parsed, err := cast.ToIntE(value)
	if err != nil {
		return 0, fmt.Errorf("config key %q: cannot parse %v as an integer", key, value)
	}
	return parsed, nil
}

func getDestName(url string, removeCommas bool) string {
	if removeCommas {
		return strings.ReplaceAll(path.Base(url), ",", "_")
	}
	return path.Base(url)
}

// DownloadCmd represents the download command
var DownloadCmd = &cobra.Command{
	Use:     "download",
	Aliases: []string{"dl"},
	Short:   "Download Apple Firmware files (and more)",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
