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
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

func init() {
	DownloadCmd.AddCommand(downloadMacosCmd)
	// Download behavior flags
	downloadMacosCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	downloadMacosCmd.Flags().Bool("insecure", false, "do not verify ssl certs")
	downloadMacosCmd.Flags().BoolP("confirm", "y", false, "do not prompt user for confirmation")
	downloadMacosCmd.Flags().Bool("skip-all", false, "always skip resumable IPSWs")
	downloadMacosCmd.Flags().Bool("resume-all", false, "always resume resumable IPSWs")
	downloadMacosCmd.Flags().Bool("restart-all", false, "always restart resumable IPSWs")
	// Filter flags
	downloadMacosCmd.Flags().StringP("version", "v", "", "iOS Version (i.e. 12.3.1)")
	downloadMacosCmd.Flags().StringP("build", "b", "", "iOS BuildID (i.e. 16F203)")
	// Command-specific flags
	downloadMacosCmd.Flags().BoolP("list", "l", false, "Show latest macOS installers")
	downloadMacosCmd.Flags().StringP("work-dir", "w", "", "macOS installer creator working directory")
	downloadMacosCmd.Flags().BoolP("assistant", "a", false, "Only download the InstallAssistant.pkg")
	downloadMacosCmd.Flags().Bool("latest", false, "Download latest macOS installer")
	// downloadMacosCmd.Flags().BoolP("kernel", "k", false, "Extract kernelcache from remote installer")
	// Bind persistent flags
	viper.BindPFlag("download.macos.proxy", downloadMacosCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("download.macos.insecure", downloadMacosCmd.Flags().Lookup("insecure"))
	viper.BindPFlag("download.macos.confirm", downloadMacosCmd.Flags().Lookup("confirm"))
	viper.BindPFlag("download.macos.skip-all", downloadMacosCmd.Flags().Lookup("skip-all"))
	viper.BindPFlag("download.macos.resume-all", downloadMacosCmd.Flags().Lookup("resume-all"))
	viper.BindPFlag("download.macos.restart-all", downloadMacosCmd.Flags().Lookup("restart-all"))
	viper.BindPFlag("download.macos.version", downloadMacosCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.macos.build", downloadMacosCmd.Flags().Lookup("build"))
	// Bind command-specific flags
	viper.BindPFlag("download.macos.list", downloadMacosCmd.Flags().Lookup("list"))
	viper.BindPFlag("download.macos.work-dir", downloadMacosCmd.Flags().Lookup("work-dir"))
	viper.BindPFlag("download.macos.assistant", downloadMacosCmd.Flags().Lookup("assistant"))
	viper.BindPFlag("download.macos.latest", downloadMacosCmd.Flags().Lookup("latest"))
	// viper.BindPFlag("download.macos.kernel", downloadMacosCmd.Flags().Lookup("kernel"))
}

// downloadMacosCmd represents the macos command
var downloadMacosCmd = &cobra.Command{
	Use:     "macos",
	Aliases: []string{"m", "mac"},
	Short:   "Download macOS installers",
	Example: heredoc.Doc(`
		# List available macOS installers
		❯ ipsw download macos --list

		# Download latest macOS installer
		❯ ipsw download macos --latest

		# Download specific macOS version
		❯ ipsw download macos --version 14.0

		# Download only InstallAssistant.pkg
		❯ ipsw download macos --version 14.0 --assistant
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// settings
		proxy := viper.GetString("download.macos.proxy")
		insecure := viper.GetBool("download.macos.insecure")
		confirm := viper.GetBool("download.macos.confirm")
		skipAll := viper.GetBool("download.macos.skip-all")
		resumeAll := viper.GetBool("download.macos.resume-all")
		restartAll := viper.GetBool("download.macos.restart-all")
		// filters
		version := viper.GetString("download.macos.version")
		build := viper.GetString("download.macos.build")
		// flags
		showInstallers := viper.GetBool("download.macos.list")
		workDir := viper.GetString("download.macos.work-dir")
		assistantOnly := viper.GetBool("download.macos.assistant")
		latest := viper.GetBool("download.macos.latest")
		// remoteKernel := viper.GetString("download.macos.kernel")
		// verify args
		if len(version) > 0 && len(build) > 0 {
			return fmt.Errorf("you cannot supply a --version AND a --build (they are mutually exclusive)")
		} else if (len(version) > 0 || len(build) > 0) && latest {
			return fmt.Errorf("you cannot supply a --latest AND (--version OR --build) (they are mutually exclusive)")
		}

		prods, err := download.GetProductInfo(latest)
		if err != nil {
			return err
		}

		if showInstallers {
			headers := []string{"Title", "Version", "Build", "Post Date"}
			data := [][]string{}
			for _, pinfo := range prods {
				data = append(data, []string{
					pinfo.Title,
					pinfo.Version,
					pinfo.Build,
					pinfo.PostDate.Format("02Jan2006 15:04:05"),
				})
			}
			if term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd())) {
				model := table.NewInteractiveTableWithTitle("🍎 macOS Installers", headers, data, false)
				p := tea.NewProgram(model, tea.WithAltScreen())
				if _, err := p.Run(); err != nil {
					return fmt.Errorf("error running interactive table: %w", err)
				}
			} else {
				// Fallback to static styled table for non-TTY environments
				bubbleTable := table.NewBubbleTable(headers, false)
				bubbleTable.SetData(data)
				fmt.Println(bubbleTable.RenderStatic())
			}
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
					return nil
				}
				return err
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
					return nil
				}
				return err
			}
		}

		if cont {
			for _, prod := range prods {
				if err := prod.DownloadInstaller(workDir, proxy, insecure, skipAll, resumeAll, restartAll, assistantOnly); err != nil {
					return err
				}
			}
		}

		return nil
	},
}
