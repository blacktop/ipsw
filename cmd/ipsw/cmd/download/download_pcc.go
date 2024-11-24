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
package download

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(pccCmd)

	pccCmd.Flags().BoolP("info", "i", false, "Show PCC Release info")
	// TODO: write to '/var/root/Library/Application Support/com.apple.security-research.pccvre/instances/<NAME>' to create a PCC VM w/o needing to set the csrutil first
	pccCmd.Flags().StringP("output", "o", "", "Output directory to save files to")
	viper.BindPFlag("download.pcc.info", pccCmd.Flags().Lookup("info"))
	viper.BindPFlag("download.pcc.output", pccCmd.Flags().Lookup("output"))

	pccCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("device")
		DownloadCmd.PersistentFlags().MarkHidden("model")
		DownloadCmd.PersistentFlags().MarkHidden("version")
		DownloadCmd.PersistentFlags().MarkHidden("build")
		DownloadCmd.PersistentFlags().MarkHidden("confirm")
		DownloadCmd.PersistentFlags().MarkHidden("remove-commas")
		c.Parent().HelpFunc()(c, s)
	})

	pccCmd.MarkFlagDirname("output")
}

// pccCmd represents the pcc command
var pccCmd = &cobra.Command{
	Use:           "pcc",
	Aliases:       []string{"p", "vre", "pccvre"},
	Short:         "Download PCC VM files",
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		// skipAll := viper.GetBool("download.skip-all")
		// resumeAll := viper.GetBool("download.resume-all")
		// restartAll := viper.GetBool("download.restart-all")

		releases, err := download.GetPCCReleases(proxy, insecure)
		if err != nil {
			return err
		}
		sort.Sort(download.ByPccIndex(releases))

		if len(releases) == 0 {
			return fmt.Errorf("no PCC Releases found")
		}

		if viper.GetBool("download.pcc.info") {
			log.Infof("Found %d PCC Releases", len(releases))
			for _, release := range releases {
				fmt.Println(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
				fmt.Println(release)
				fmt.Println(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
			}
		} else {
			var choices []string
			for _, r := range releases {
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
