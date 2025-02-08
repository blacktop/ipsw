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
package download

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DownloadCmd.AddCommand(macosCmd)

	macosCmd.Flags().BoolP("list", "l", false, "Show latest macOS installers")
	macosCmd.Flags().StringP("work-dir", "w", "", "macOS installer creator working directory")
	macosCmd.Flags().Bool("ignore", false, "Do NOT verify pkg digests")
	macosCmd.Flags().BoolP("assistant", "a", false, "Only download the InstallAssistant.pkg")
	macosCmd.Flags().Bool("latest", false, "Download latest macOS installer")
	// macosCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote installer")
	macosCmd.SetHelpFunc(func(c *cobra.Command, s []string) {
		DownloadCmd.PersistentFlags().MarkHidden("white-list")
		DownloadCmd.PersistentFlags().MarkHidden("black-list")
		DownloadCmd.PersistentFlags().MarkHidden("device")
		DownloadCmd.PersistentFlags().MarkHidden("model")
		c.Parent().HelpFunc()(c, s)
	})
	viper.BindPFlag("download.macos.list", macosCmd.Flags().Lookup("list"))
	viper.BindPFlag("download.macos.work-dir", macosCmd.Flags().Lookup("work-dir"))
	viper.BindPFlag("download.macos.ignore", macosCmd.Flags().Lookup("ignore"))
	viper.BindPFlag("download.macos.assistant", macosCmd.Flags().Lookup("assistant"))
	viper.BindPFlag("download.macos.latest", macosCmd.Flags().Lookup("latest"))
	// viper.BindPFlag("download.macos.kernel", macosCmd.Flags().Lookup("kernel"))
}

// macosCmd represents the macos command
var macosCmd = &cobra.Command{
	Use:           "macos",
	Aliases:       []string{"m", "mac"},
	Short:         "Download macOS installers",
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		viper.BindPFlag("download.proxy", cmd.Flags().Lookup("proxy"))
		viper.BindPFlag("download.insecure", cmd.Flags().Lookup("insecure"))
		viper.BindPFlag("download.confirm", cmd.Flags().Lookup("confirm"))
		viper.BindPFlag("download.skip-all", cmd.Flags().Lookup("skip-all"))
		viper.BindPFlag("download.resume-all", cmd.Flags().Lookup("resume-all"))
		viper.BindPFlag("download.restart-all", cmd.Flags().Lookup("restart-all"))
		viper.BindPFlag("download.version", cmd.Flags().Lookup("version"))
		viper.BindPFlag("download.build", cmd.Flags().Lookup("build"))

		cmd.Flags().Lookup("remove-commas").Hidden = true

		// settings
		proxy := viper.GetString("download.proxy")
		insecure := viper.GetBool("download.insecure")
		confirm := viper.GetBool("download.confirm")
		skipAll := viper.GetBool("download.skip-all")
		resumeAll := viper.GetBool("download.resume-all")
		restartAll := viper.GetBool("download.restart-all")
		// filters
		version := viper.GetString("download.version")
		build := viper.GetString("download.build")
		// flags
		showInstallers := viper.GetBool("download.macos.list")
		workDir := viper.GetString("download.macos.work-dir")
		ignoreSha1 := viper.GetBool("download.macos.ignore")
		assistantOnly := viper.GetBool("download.macos.assistant")
		latest := viper.GetBool("download.macos.latest")
		// remoteKernel := viper.GetString("download.macos.kernel")

		// verify args
		if len(version) > 0 && len(build) > 0 {
			return fmt.Errorf("you cannot supply a --version AND a --build (they are mutually exclusive)")
		} else if (len(version) > 0 || len(build) > 0) && latest {
			return fmt.Errorf("you cannot supply a --latest AND (--version OR --build) (they are mutually exclusive)")
		}

		prods, err := download.GetProductInfo()
		if err != nil {
			return err
		}

		if showInstallers {
			fmt.Println(prods)
			return nil
		}

		// filter installers
		if len(version) > 0 {
			prods = prods.FilterByVersion(version)
		} else if len(build) > 0 {
			prods = prods.FilterByBuild(build)
		} else if latest {
			prods = prods.GetLatest()
		}

		var prodList []string
		for _, p := range prods {
			prodList = append(prodList, fmt.Sprintf("%-35s%-8s %-8s %s", p.Title, p.Version, p.Build, p.PostDate.Format("02Jan2006 15:04:05")))
		}

		if len(prodList) == 0 {
			return fmt.Errorf("no installers found for given options")
		}

		if len(prodList) > 1 && len(build) == 0 && !latest {
			choices := []int{}
			survey.MultiSelectQuestionTemplate = `
	{{- define "option"}}
	    {{- if eq .SelectedIndex .CurrentIndex }}{{color .Config.Icons.SelectFocus.Format }}{{ .Config.Icons.SelectFocus.Text }}{{color "reset"}}{{else}} {{end}}
	    {{- if index .Checked .CurrentOpt.Index }}{{color .Config.Icons.MarkedOption.Format }} {{ .Config.Icons.MarkedOption.Text }} {{else}}{{color .Config.Icons.UnmarkedOption.Format }} {{ .Config.Icons.UnmarkedOption.Text }} {{end}}
	    {{- color "reset"}}
	    {{- " "}}{{- .CurrentOpt.Value}}
	{{end}}
	{{- if .ShowHelp }}{{- color .Config.Icons.Help.Format }}{{ .Config.Icons.Help.Text }} {{ .Help }}{{color "reset"}}{{"\n"}}{{end}}
	{{- color .Config.Icons.Question.Format }}{{ .Config.Icons.Question.Text }} {{color "reset"}}
	{{- color "default+hb"}}{{ .Message }}{{ .FilterMessage }}{{color "reset"}}
	{{- if .ShowAnswer}}{{color "cyan"}} ✅{{color "reset"}}{{"\n"}}
	{{- else }}
		{{- "  "}}{{- color "cyan"}}[Use arrows to move, space to select, <right> to all, <left> to none, type to filter{{- if and .Help (not .ShowHelp)}}, {{ .Config.HelpInput }} for more help{{end}}]{{color "reset"}}
	  {{- "\n"}}
	  {{- range $ix, $option := .PageEntries}}
	    {{- template "option" $.IterateOption $ix $option}}
	  {{- end}}
	{{- end}}`
			prompt := &survey.MultiSelect{
				Message:  "Choose installer(s):",
				Options:  prodList,
				PageSize: 25,
			}
			if err := survey.AskOne(prompt, &choices); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				log.Fatal(err.Error())
			}
			var chosenProds []download.ProductInfo
			for choice := range choices {
				chosenProds = append(chosenProds, prods[choice])
			}
			prods = chosenProds
		}

		cont := true
		if !confirm {
			msg := fmt.Sprintf("You are about to download %d installer(s). Continue?", len(prods))
			if assistantOnly {
				msg = fmt.Sprintf("You are about to download %d InstallAssistant.pkg(s). Continue?", len(prods))
			}
			prompt := &survey.Confirm{
				Message: msg,
			}
			if err := survey.AskOne(prompt, &cont); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				log.Fatal(err.Error())
			}
		}

		if cont {
			for _, prod := range prods {
				if err := prod.DownloadInstaller(workDir, proxy, insecure, skipAll, resumeAll, restartAll, ignoreSha1, assistantOnly); err != nil {
					return err
				}
			}
		}

		return nil
	},
}
