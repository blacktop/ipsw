/*
Copyright © 2026 blacktop

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
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
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
	downloadPccCmd.Flags().String("version", "", "Filter by OS ProductVersion prefix (e.g. 26.3); resolved via partial-zip, cached")
	downloadPccCmd.Flags().String("build", "", "Filter by cloudOS build version prefix (e.g. 5E, 5E290)")
	downloadPccCmd.Flags().String("train", "", "Filter by cloudOS build train substring (e.g. LuckE)")
	downloadPccCmd.Flags().String("app", "", "Filter by cloudOS application name (e.g. TIE, 'TIE Proxy')")
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
	viper.BindPFlag("download.pcc.version", downloadPccCmd.Flags().Lookup("version"))
	viper.BindPFlag("download.pcc.build", downloadPccCmd.Flags().Lookup("build"))
	viper.BindPFlag("download.pcc.train", downloadPccCmd.Flags().Lookup("train"))
	viper.BindPFlag("download.pcc.app", downloadPccCmd.Flags().Lookup("app"))
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

		# Filter by cloudOS build prefix and pick interactively
		❯ ipsw download pcc --build 5E --app TIE

		# Download PCC VM files interactively
		❯ ipsw download pcc

		# Download to specific directory
		❯ ipsw download pcc --output ./pcc-vms
	`),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// settings
		proxy := viper.GetString("download.pcc.proxy")
		insecure := viper.GetBool("download.pcc.insecure")
		// skipAll := viper.GetBool("download.pcc.skip-all")
		// resumeAll := viper.GetBool("download.pcc.resume-all")
		// restartAll := viper.GetBool("download.pcc.restart-all")
		versionFilter := viper.GetString("download.pcc.version")
		buildFilter := viper.GetString("download.pcc.build")
		trainFilter := viper.GetString("download.pcc.train")
		appFilter := viper.GetString("download.pcc.app")

		var bar func(done, total uint64)
		var clearBar func()
		if isatty.IsTerminal(os.Stderr.Fd()) {
			p := progress.New(progress.WithDefaultGradient(), progress.WithWidth(40), progress.WithoutPercentage())
			clearBar = func() { fmt.Fprint(os.Stderr, "\r\033[K") }
			bar = func(done, total uint64) {
				fmt.Fprintf(os.Stderr, "\r   • Fetching PCC log %s %d/%d", p.ViewAs(float64(done)/float64(total)), done, total)
				if done >= total {
					clearBar()
				}
			}
		}
		releases, err := download.GetPCCReleases(proxy, insecure, bar)
		if err != nil {
			if clearBar != nil {
				clearBar()
			}
			return err
		}

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
		} else {
			releases = download.UniquePCCReleases(releases)
		}

		if buildFilter != "" || trainFilter != "" || appFilter != "" {
			filtered := releases[:0]
			for _, r := range releases {
				build, train, app := r.CloudOSInfo()
				if buildFilter != "" && !strings.HasPrefix(build, buildFilter) {
					continue
				}
				if trainFilter != "" && !strings.Contains(train, trainFilter) {
					continue
				}
				if appFilter != "" && app != appFilter {
					continue
				}
				filtered = append(filtered, r)
			}
			releases = filtered
		}

		// Version filter requires network on first use; runs after the cheap
		// metadata filters so we resolve as few URLs as possible. Resolution
		// attaches PCCVersion to each release in-place and persists to the
		// unified pcc_log.json cache.
		if versionFilter != "" {
			download.ResolvePCCVersions(releases, pccVersionFetcher(proxy, insecure))
			filtered := releases[:0]
			for _, r := range releases {
				if r.Version != nil && strings.HasPrefix(r.Version.Version, versionFilter) {
					filtered = append(filtered, r)
				}
			}
			releases = filtered
		}

		// Log index does not track chronology — releases can be appended out
		// of build order. Sort by the metadata timestamp so newest is first.
		sort.Slice(releases, func(i, j int) bool {
			return releases[i].ReleaseCreationTime().After(releases[j].ReleaseCreationTime())
		})

		if len(releases) == 0 {
			return fmt.Errorf("no PCC Releases found")
		}

		if viper.GetBool("download.pcc.info") {
			log.Infof("Found %d PCC Releases", len(releases))
			// Resolve any releases whose VPhone hasn't been populated yet from
			// the cache; new entries since the last run pay the partial-zip
			// cost once and persist the result.
			download.ResolveVPhoneFirmware(releases, pccVPhoneFetcher(proxy, insecure))
			for i := range releases {
				release := releases[i]
				fmt.Println(" ╭╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
				fmt.Println(release)
				if release.Version != nil {
					utils.Indent(log.WithFields(log.Fields{"version": release.Version.Version, "build": release.Version.Build}).Info, 1)("OS IPSW")
				} else if len(releases) == 1 {
					if v, err := pccVersionFetcher(proxy, insecure)(release.OSAssetURL()); err == nil {
						utils.Indent(log.WithFields(log.Fields{"version": v.Version, "build": v.Build}).Info, 1)("OS IPSW")
					}
				}
				printVPhoneBanner(release.VRE(), release.VPhone)
				fmt.Println(" ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴")
			}
		} else {
			// Picker reads what's already in the cache via release.VPhone —
			// no network calls. Uncached releases show a blank tag; run
			// --info once to warm the cache for next time.
			var choices []string
			for i := range releases {
				r := releases[i]
				build, train, app := r.CloudOSInfo()
				label := build
				if r.Version != nil {
					label = r.Version.Version + " " + build
				}
				if train != "" {
					label += " (" + train + ")"
				}
				if app != "" {
					label += "  " + app
				}
				if label == "" {
					label = r.ReleaseID()
				}
				choices = append(choices, fmt.Sprintf("%s %05d: %-52s [created: %s]",
					vphoneTag(r.VRE(), r.VPhone),
					r.Index,
					label,
					r.ReleaseCreationTime().Format("2006-01-02 15:04:05"),
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
			r := releases[choice]
			out := viper.GetString("download.pcc.output")
			if out == "" {
				build, _, _ := r.CloudOSInfo()
				out = fmt.Sprintf("PCC_%d_%s", r.Index, build)
			}
			log.Infof("Downloading PCC Release %d to %s", r.Index, out)
			return r.Download(out, proxy, insecure)
		}

		return nil
	},
}

// pccVPhoneFetcher partial-zips an OS asset's central directory and reports
// whether the IPSW carries vphone600 research-device firmware. Apple shipped
// vphone600 through cloudOS train 5E (iOS 26.3); train 5F (iOS 26.4) dropped
// it, breaking iPhone-shaped virtualization (vphone-cli). Only the zip
// listing is fetched — no file body reads — so this is cheap.
func pccVPhoneFetcher(proxy string, insecure bool) func(url string) (download.VPhoneFirmware, error) {
	return func(url string) (download.VPhoneFirmware, error) {
		zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{Proxy: proxy, Insecure: insecure})
		if err != nil {
			return download.VPhoneFirmware{}, err
		}
		var count int
		for _, f := range zr.File {
			if strings.Contains(f.Name, download.VPhoneFirmwareToken) {
				count++
			}
		}
		return download.VPhoneFirmware{Present: count > 0, Count: count}, nil
	}
}

// vphoneState classifies a release into one of four display buckets shared
// by the --info banner and the interactive-picker tag.
type vphoneState int

const (
	vphoneUnknown vphoneState = iota // not in cache, no metadata signal
	vphoneVRE                        // metadata says VRE but firmware not checked
	vphonePresent                    // firmware present in IPSW
	vphoneMissing                    // firmware absent — the alert signal
)

// vphoneDisplay holds the strings + color + log level for each state, so the
// picker tag and the --info banner can't drift on the next edit.
//
// tag is 7 cells wide on wide-emoji terminals; warn drives apex/log color.
var vphoneDisplay = map[vphoneState]struct {
	tag, banner, detail string
	color               func(...any) string
	warn                bool
}{
	vphonePresent: {"📱VPHN ", "📱 VPHONE", "vphone600 firmware present", color.New(color.Bold, color.FgHiGreen).SprintFunc(), false},
	vphoneMissing: {"🚫NONE ", "🚫 NO VPHONE", "vphone600 firmware REMOVED — vresearch-only", color.New(color.Bold, color.FgHiRed).SprintFunc(), true},
	vphoneVRE:     {"⬢VRE   ", "⬢ VRE", "metadata-only marker — IPSW firmware not checked", color.New(color.Bold, color.FgHiYellow).SprintFunc(), true},
	vphoneUnknown: {"       ", "", "", nil, false},
}

func vphoneClassify(vre download.VRESignals, v *download.VPhoneFirmware) vphoneState {
	// Only VRE releases get the missing-firmware alert. A non-VRE release
	// without vphone600 was never expected to have it — silently classify
	// as unknown so the picker tag and --info banner stay clean.
	switch {
	case v != nil && v.Present:
		return vphonePresent
	case v != nil && vre.IsVRE():
		return vphoneMissing
	case vre.IsVRE():
		return vphoneVRE
	default:
		return vphoneUnknown
	}
}

func vphoneTag(vre download.VRESignals, v *download.VPhoneFirmware) string {
	return vphoneDisplay[vphoneClassify(vre, v)].tag
}

// printVPhoneBanner emits a one-line, indented status line at the bottom of
// each --info release block. The missing branch is the alert signal.
func printVPhoneBanner(vre download.VRESignals, v *download.VPhoneFirmware) {
	d := vphoneDisplay[vphoneClassify(vre, v)]
	if d.banner == "" {
		return
	}
	fields := log.Fields{"device": vre.Device}
	if v != nil && v.Count > 0 {
		fields["count"] = v.Count
	}
	msg := d.color(d.banner) + "  " + d.detail
	if d.warn {
		utils.Indent(log.WithFields(fields).Warn, 2)(msg)
	} else {
		utils.Indent(log.WithFields(fields).Info, 2)(msg)
	}
}

// pccVersionFetcher returns a closure that partial-zips an OS asset to read
// only BuildManifest.plist (info.ParseZipFiles would also pull every other
// plist plus parse all DeviceTree im4p files). ~85% of releases serve Range
// requests; the newest few sometimes 403 before CDN sync.
func pccVersionFetcher(proxy string, insecure bool) func(url string) (download.PCCVersion, error) {
	return func(url string) (download.PCCVersion, error) {
		if url == "" {
			return download.PCCVersion{}, fmt.Errorf("no OS asset URL")
		}
		zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{Proxy: proxy, Insecure: insecure})
		if err != nil {
			return download.PCCVersion{}, err
		}
		for _, f := range zr.File {
			if path.Base(f.Name) != "BuildManifest.plist" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return download.PCCVersion{}, err
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return download.PCCVersion{}, err
			}
			bm, err := plist.ParseBuildManifest(data)
			if err != nil {
				return download.PCCVersion{}, err
			}
			return download.PCCVersion{Version: bm.ProductVersion, Build: bm.ProductBuildVersion}, nil
		}
		return download.PCCVersion{}, fmt.Errorf("no BuildManifest in IPSW")
	}
}
