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
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	pcccmd "github.com/blacktop/ipsw/internal/commands/pcc"
	"github.com/blacktop/ipsw/internal/commands/watch"
	"github.com/blacktop/ipsw/internal/commands/watch/announce"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const pccWatchRequestTimeout = 2 * time.Minute

func init() {
	watchCmd.AddCommand(watchPCCCmd)

	watchPCCCmd.Flags().DurationP("interval", "t", 5*time.Minute, "Polling interval (0 runs once)")
	watchPCCCmd.Flags().String("state", "", "Path to durable PCC watcher state")
	watchPCCCmd.Flags().Bool("notify-initial", false, "Notify for existing vphone600 releases when creating state")
	watchPCCCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	watchPCCCmd.Flags().Bool("insecure", false, "Do not verify TLS certificates")

	viper.BindPFlag("watch.pcc.interval", watchPCCCmd.Flags().Lookup("interval"))
	viper.BindPFlag("watch.pcc.state", watchPCCCmd.Flags().Lookup("state"))
	viper.BindPFlag("watch.pcc.notify-initial", watchPCCCmd.Flags().Lookup("notify-initial"))
	viper.BindPFlag("watch.pcc.proxy", watchPCCCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("watch.pcc.insecure", watchPCCCmd.Flags().Lookup("insecure"))
}

var watchPCCCmd = &cobra.Command{
	Use:   "pcc",
	Short: "Watch for new PCC vphone600 firmware",
	Example: heredoc.Doc(`
		# Watch for new vphone600 firmware and print notifications
		❯ ipsw watch pcc

		# Announce new vphone600 firmware to Discord
		❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch pcc --discord --interval 5m

		# Initialize state and notify for existing vphone600 releases
		❯ ipsw watch pcc --notify-initial --interval 0
	`),
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		interval := viper.GetDuration("watch.pcc.interval")
		if interval < 0 {
			return fmt.Errorf("--interval must be greater than or equal to zero")
		}
		if viper.GetBool("watch.discord") {
			if err := validateDiscordFlags(); err != nil {
				return err
			}
		}

		statePath := viper.GetString("watch.pcc.state")
		if statePath == "" {
			var err error
			statePath, err = watch.DefaultPCCVPhoneStatePath()
			if err != nil {
				return err
			}
		} else {
			statePath = expandPath(statePath)
		}
		state, err := watch.LoadPCCVPhoneState(statePath)
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		remoteClient := download.NewRemoteHTTPClient(
			viper.GetString("watch.pcc.proxy"),
			viper.GetBool("watch.pcc.insecure"),
		)
		remoteClient.Timeout = pccWatchRequestTimeout

		config := pccWatchConfig{
			statePath:     statePath,
			notifyInitial: viper.GetBool("watch.pcc.notify-initial"),
			proxy:         viper.GetString("watch.pcc.proxy"),
			insecure:      viper.GetBool("watch.pcc.insecure"),
			discord:       viper.GetBool("watch.discord"),
			discordConfig: announce.DiscordConfig{
				DiscordWebhookID:    viper.GetString("watch.discord-id"),
				DiscordWebhookToken: viper.GetString("watch.discord-token"),
				DiscordColor:        "0x5865F2",
				DiscordAuthor:       "📱 PCC VPHONE",
				DiscordIconURL:      viper.GetString("watch.discord-icon"),
			},
			remoteClient: remoteClient,
			output:       cmd.OutOrStdout(),
		}

		for {
			nextState, err := pollPCCVPhone(ctx, state, config)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				if interval == 0 {
					return err
				}
				log.Errorf("PCC vphone watch failed: %v", err)
			} else {
				state = nextState
			}

			if interval == 0 {
				return nil
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	},
}

type pccWatchConfig struct {
	statePath     string
	notifyInitial bool
	proxy         string
	insecure      bool
	discord       bool
	discordConfig announce.DiscordConfig
	remoteClient  *http.Client
	output        io.Writer
}

func pollPCCVPhone(
	ctx context.Context,
	state watch.PCCVPhoneState,
	config pccWatchConfig,
) (watch.PCCVPhoneState, error) {
	pollCtx, cancel := context.WithTimeout(ctx, pccWatchRequestTimeout)
	defer cancel()

	snapshot, err := download.GetPCCLogSnapshot(
		pollCtx,
		config.proxy,
		config.insecure,
		nil,
	)
	if err != nil {
		return state, fmt.Errorf("failed to fetch PCC transparency log: %w", err)
	}

	pollClient := pccWatchHTTPClient(pollCtx, config.remoteClient)
	remoteConfig := &download.RemoteConfig{Client: pollClient}
	check := watch.CheckPCCVPhoneSnapshot(
		state,
		snapshot,
		config.notifyInitial,
		func(releases []*download.PCCRelease) {
			download.ResolveVPhoneFirmware(releases, pcccmd.VPhoneFetcher(remoteConfig))
		},
	)

	if len(check.NewReleases) > 0 {
		download.ResolvePCCVersions(check.NewReleases, pcccmd.VersionFetcher(remoteConfig))
		if config.discord {
			for _, message := range pccVPhoneDiscordNotifications(check.NewReleases) {
				if err := announce.DiscordContext(pollCtx, pollClient, message, &config.discordConfig); err != nil {
					return state, fmt.Errorf("discord announce failed: %w", err)
				}
			}
		} else if _, err := fmt.Fprintln(config.output, pccVPhoneNotification(check.NewReleases)); err != nil {
			return state, fmt.Errorf("failed to write PCC vphone notification: %w", err)
		}
	}

	if err := watch.SavePCCVPhoneState(config.statePath, check.State); err != nil {
		return state, err
	}
	if check.Baselined {
		log.Infof("Initialized PCC vphone watch state at log index %d", check.State.HeadIndex)
	}
	if check.Pending > 0 {
		log.Warnf("%d PCC OS asset(s) could not be resolved and will be retried", check.Pending)
	}
	return check.State, nil
}

func pccVPhoneNotification(releases []*download.PCCRelease) string {
	var out strings.Builder
	if len(releases) == 1 {
		out.WriteString("New PCC vphone600 firmware\n\n")
	} else {
		fmt.Fprintf(&out, "%d new PCC vphone600 firmware releases\n\n", len(releases))
	}
	for index, release := range releases {
		if index > 0 {
			out.WriteString("\n\n")
		}
		out.WriteString(pcccmd.ReleaseSummary(release))
		if osURL := release.OSAssetURL(); osURL != "" {
			fmt.Fprintf(&out, "\n  OS           %s", osURL)
		}
	}
	return out.String()
}

func pccVPhoneDiscordNotifications(releases []*download.PCCRelease) []string {
	messages := make([]string, 0, len(releases))
	for _, release := range releases {
		messages = append(messages, pccVPhoneNotification([]*download.PCCRelease{release}))
	}
	return messages
}

type pccWatchTransport struct {
	ctx  context.Context
	base http.RoundTripper
}

func (transport pccWatchTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport.base.RoundTrip(request.Clone(transport.ctx))
}

func pccWatchHTTPClient(ctx context.Context, client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	pollClient := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	pollClient.Transport = pccWatchTransport{ctx: ctx, base: base}
	return &pollClient
}
