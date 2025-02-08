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
package download

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadKeysCmd)

	// downloadKeysCmd.Flags().Bool("beta", false, "Download beta keys")
	downloadKeysCmd.Flags().Bool("json", false, "Output as JSON")
	downloadKeysCmd.Flags().StringP("output", "o", "", "Folder to download keys to")
	downloadKeysCmd.MarkFlagDirname("output")
	downloadKeysCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("model")
		c.Parent().HelpFunc()(c, s)
	})
	// viper.BindPFlag("download.keys.beta", downloadKeysCmd.Flags().Lookup("beta"))
	viper.BindPFlag("download.keys.json", downloadKeysCmd.Flags().Lookup("json"))
	viper.BindPFlag("download.keys.output", downloadKeysCmd.Flags().Lookup("output"))
}

// downloadKeysCmd represents the keys command
var downloadKeysCmd = &cobra.Command{
	Use:           "keys",
	Short:         "Download FW keys from The iPhone Wiki",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.device", cmd.Flags().Lookup("device"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		// filters
		device := viper.GetString("download.device")
		version := viper.GetString("download.version")
		build := viper.GetString("download.build")
		// flags
		asJSON := viper.GetBool("download.keys.json")
		output := viper.GetString("download.keys.output")

		// validate flags
		if len(device) == 0 {
			return fmt.Errorf("please supply a --device")
		}
		if len(version) == 0 && len(build) == 0 {
			return fmt.Errorf("please supply a --version OR --build")
		}
		if len(build) == 0 && len(version) > 0 {
			build, err = download.GetBuildID(version, device)
			if err != nil {
				return fmt.Errorf("failed to query ipsw.me api for --version %s (please supply '--build' instead): %v", version, err)
			}
		}

		log.Info("Downloading Keys...")
		keys, err := download.GetWikiFirmwareKeys(&download.WikiConfig{
			Keys:    true,
			Device:  device,
			Version: version,
			Build:   build,
			// Beta:    viper.GetBool("download.key.beta"),
		}, proxy, insecure)
		if err != nil {
			return fmt.Errorf("failed querying theapplewiki.com: %v", err)
		}

		if len(output) > 0 || asJSON {
			dat, err := json.Marshal(keys)
			if err != nil {
				log.Errorf("failed to marshal keys metadata: %v", err)
			}
			if asJSON {
				fmt.Println(string(dat))
				return nil
			}
			name := fmt.Sprintf("keys_%s_%s.json", device, build)
			if err := os.MkdirAll(output, 0o750); err != nil {
				log.Errorf("failed to create output folder: %v", err)
			}
			name = filepath.Join(output, name)
			log.Infof("Writing keys to: %s", name)
			if err := os.WriteFile(name, dat, 0o660); err != nil {
				log.Errorf("failed to write IPSW metadata: %v", err)
			}
		} else {
			for _, val := range keys {
				fmt.Println(val)
			}
		}

		return nil
	},
}
