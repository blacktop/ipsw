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
	"math"
	"path"
	"strings"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.PersistentFlags().Int("parts", 0,
		"maximum parallel connections per download (0 uses the URL profile)")
	DownloadCmd.PersistentFlags().Int("min-parts", 0,
		"connections opened immediately and never retired (0 uses the URL profile)")
	DownloadCmd.PersistentFlags().Int("min-part-size", 0,
		"minimum scheduler range size in MiB (0 uses the URL profile)")
	DownloadCmd.PersistentFlags().Bool("enable-node-selection", false,
		"spread streams across CDN addresses by measured throughput")
	viper.BindPFlag("download.parts", DownloadCmd.PersistentFlags().Lookup("parts"))
	viper.BindPFlag("download.min-parts", DownloadCmd.PersistentFlags().Lookup("min-parts"))
	viper.BindPFlag("download.min-part-size",
		DownloadCmd.PersistentFlags().Lookup("min-part-size"))
	viper.BindPFlag("download.enable-node-selection",
		DownloadCmd.PersistentFlags().Lookup("enable-node-selection"))
}

// ApplyDownloadPolicy resolves the download policy overrides (flags, config, or
// environment) and installs them process-wide. Integer zero retains the
// profile chosen from each URL.
func ApplyDownloadPolicy() error {
	parts, err := configInt("download.parts")
	if err != nil {
		return err
	}
	minParts, err := configInt("download.min-parts")
	if err != nil {
		return err
	}
	minPartSizeMiB, err := configInt("download.min-part-size")
	if err != nil {
		return err
	}
	// bound before shifting: a negative value with |v| > 2^43 would wrap to
	// a huge positive byte count and dodge the engine's >= 0 validation
	if minPartSizeMiB < 0 {
		return fmt.Errorf("config key %q: must be >= 0 MiB, got %d",
			"download.min-part-size", minPartSizeMiB)
	}
	if int64(minPartSizeMiB) > math.MaxInt64>>20 {
		return fmt.Errorf("config key %q: value is too large", "download.min-part-size")
	}
	return download.SetPolicyOverrides(download.PolicyOverrides{
		Parts:               parts,
		MinParts:            minParts,
		MinPartSize:         int64(minPartSizeMiB) << 20,
		EnableNodeSelection: configBool("download.enable-node-selection"),
	})
}

// configValue reads a download.* config key, falling back to the compiled
// flag default when viper was reset (tests) or the binding is gone.
func configValue(key string) any {
	value := viper.Get(key)
	if value == nil {
		if f := DownloadCmd.PersistentFlags().Lookup(strings.TrimPrefix(key, "download.")); f != nil {
			value = f.Value.String()
		}
	}
	return value
}

func configBool(key string) bool {
	return cast.ToBool(configValue(key))
}

func configInt(key string) (int, error) {
	value := configValue(key)
	// cast.ToIntE silently truncates floats and converts bools: reject both
	// so a config typo cannot become a different-but-valid policy value
	switch v := value.(type) {
	case bool:
		return 0, fmt.Errorf("config key %q: cannot parse %v as an integer", key, v)
	case float64:
		if v != math.Trunc(v) {
			return 0, fmt.Errorf("config key %q: cannot parse %v as an integer", key, v)
		}
	case float32:
		if float64(v) != math.Trunc(float64(v)) {
			return 0, fmt.Errorf("config key %q: cannot parse %v as an integer", key, v)
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
	Long: `Download Apple firmware files, Developer Portal artifacts, App Store
packages, and other supported resources.

On an eligible direct CDN, --enable-node-selection spreads a multipart
download's range requests across the host's resolved addresses, measures
their throughput with real file bytes, and moves unfinished work away from
consistently slow addresses. It stays opt-in because some CDN routes are
faster without placement. Use --verbose to see whether placement activated
and which addresses were connected.`,
	Example: heredoc.Doc(`
		# Opt into measured multi-address placement for an Apple CDN download
		❯ ipsw download ipsw --device iPhone16,1 --latest --enable-node-selection`),
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
