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
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(downloadPccCmd)
	// Download behavior flags
	downloadPccCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadPccCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	downloadPccCmd.Flags().Bool("skip-all", false, "always skip resumable IPSWs")
	downloadPccCmd.Flags().Bool("resume-all", false, "always resume resumable IPSWs")
	downloadPccCmd.Flags().Bool("restart-all", false, "always restart resumable IPSWs")
	// Command-specific flags
	downloadPccCmd.Flags().BoolP("info", "i", false, "Show PCC Release info")
	// TODO: write to '/var/root/Library/Application Support/com.apple.security-research.pccvre/instances/<NAME>' to create a PCC VM w/o needing to set the csrutil first
	downloadPccCmd.Flags().StringP("output", "o", "", "Output directory to save files to")
	downloadPccCmd.MarkFlagDirname("output")
	// Bind persistent flags
	viper.BindPFlag("download.pcc.proxy", downloadPccCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.pcc.insecure", downloadPccCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.pcc.skip-all", downloadPccCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.pcc.resume-all", downloadPccCmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.pcc.restart-all", downloadPccCmd.Flags().Lookup("restart-all"))
	// Bind command-specific flags
	viper.BindPFlag("download.pcc.info", downloadPccCmd.Flags().Lookup("info"))
	viper.BindPFlag("download.pcc.output", downloadPccCmd.Flags().Lookup("output"))
}

// downloadPccCmd represents the pcc command
var downloadPccCmd = &cobra.Command{
	Use:     "pcc [INDEX]",
	Aliases: []string{"p", "vre", "pccvre"},
	Short:   "Download PCC VM files",
	Args:    cobra.MaximumNArgs(1),
	Example: heredoc.Doc(`
		# Show available PCC releases info
		❯ ipsw download pcc --info

		# Show info for specific PCC release by index
		❯ ipsw download pcc 42 --info

		# Download specific PCC release by index
		❯ ipsw download pcc 42

		# Download PCC VM files interactively
		❯ ipsw download pcc

		# Download to specific directory
		❯ ipsw download pcc --output ./pcc-vms
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		proxy := viper.GetString("download.pcc.proxy")
		insecure := viper.GetBool("download.pcc.insecure")
		// skipAll := viper.GetBool("download.pcc.skip-all")
		// resumeAll := viper.GetBool("download.pcc.resume-all")
		// restartAll := viper.GetBool("download.pcc.restart-all")

		releases, err := download.GetPCCReleases(proxy, insecure)
		if err != nil {
			return err
		}
		sort.Sort(download.ByPccIndex(releases))

		if len(releases) == 0 {
			return fmt.Errorf("no PCC Releases found")
		}

		// Filter releases if user provided a specific index
		if len(args) > 0 {
			index, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid index: %s", args[0])
			}

			// Find release with matching index
			foundIndex := -1
			for i := range releases {
				if releases[i].Index == uint64(index) {
					foundIndex = i
					break
				}
			}

			if foundIndex == -1 {
				return fmt.Errorf("no PCC release found with index %d", index)
			}

			// Replace releases list with filtered single release
			releases = releases[foundIndex : foundIndex+1]
		}

		if viper.GetBool("download.pcc.info") {
			log.Infof("Found %d PCC Releases", len(releases))
			for i := range releases {
				release := &releases[i]
				fmt.Println(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
				fmt.Println(release)
				fmt.Println(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
			}
		} else {
			var choices []string
			for i := range releases {
				r := &releases[i]
				choices = append(choices, fmt.Sprintf("%04d: %s  [created: %s]",
					r.Index,
					hex.EncodeToString(r.GetReleaseHash()),
					r.GetTimestamp().AsTime().Format("2006-01-02 15:04:05"),
				))
			}

			choice := 0
			prompt := &survey.Select{
				Message:  "PCC Release to download:",
				Options:  choices,
				PageSize: 15,
			}
			if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
				log.Warn("Exiting...")
				return nil
			}
			log.Infof("Downloading PCC Release for %d", releases[choice].Index)
			return releases[choice].Download(viper.GetString("download.pcc.output"), proxy, insecure)
		}

		return nil
	},
}
