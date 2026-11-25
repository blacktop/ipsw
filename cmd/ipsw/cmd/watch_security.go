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
	"encoding/json"
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
	"github.com/blacktop/ipsw/internal/commands/watch"
	"github.com/blacktop/ipsw/internal/commands/watch/announce"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const securityWatchRequestTimeout = time.Minute

func init() {
	watchCmd.AddCommand(watchSecurityCmd)

	watchSecurityCmd.Flags().DurationP("interval", "t", time.Hour, "Polling interval (0 runs once)")
	watchSecurityCmd.Flags().String("state", "", "Path to durable security watcher state")
	watchSecurityCmd.Flags().Bool("notify-initial", false, "Report existing advisories when creating state")
	watchSecurityCmd.Flags().StringArray("credit", nil, "Only report CVEs credited to NAME (case-insensitive substring, repeatable)")
	watchSecurityCmd.Flags().Bool("json", false, "Print one JSON event per line")
	watchSecurityCmd.Flags().String("proxy", "", "HTTP/HTTPS proxy")
	watchSecurityCmd.Flags().Bool("insecure", false, "Do not verify TLS certificates")

	viper.BindPFlag("watch.security.interval", watchSecurityCmd.Flags().Lookup("interval"))
	viper.BindPFlag("watch.security.state", watchSecurityCmd.Flags().Lookup("state"))
	viper.BindPFlag("watch.security.notify-initial", watchSecurityCmd.Flags().Lookup("notify-initial"))
	viper.BindPFlag("watch.security.credit", watchSecurityCmd.Flags().Lookup("credit"))
	viper.BindPFlag("watch.security.json", watchSecurityCmd.Flags().Lookup("json"))
	viper.BindPFlag("watch.security.proxy", watchSecurityCmd.Flags().Lookup("proxy"))
	viper.BindPFlag("watch.security.insecure", watchSecurityCmd.Flags().Lookup("insecure"))
}

var watchSecurityCmd = &cobra.Command{
	Use:   "security",
	Short: "Watch Apple security advisories for new and changed CVEs",
	Long: heredoc.Doc(`
		Watch Apple security advisories for new and changed CVEs.

		Reads the security releases table at https://support.apple.com/en-us/100100 and the
		CSAF JSON Apple publishes for advisories released on or after 2026-09-14. Apple edits
		advisories after release, so every poll re-reads each one (with conditional requests)
		and reports CVEs added or removed and changed credits, fixed products, impact or
		description. Requests are spaced 3s apart and HTTP 429 responses are retried with backoff.
	`),
	Example: heredoc.Doc(`
		# Create state silently, then report changes every hour
		❯ ipsw watch security

		# One-shot scan that lists every CVE credited to a researcher
		❯ ipsw watch security --interval 0 --notify-initial --credit "Jane Doe" --state /tmp/sec.json

		# Stream events as JSON lines for scripts and agents
		❯ ipsw watch security --json --interval 30m

		# Announce changes to Discord
		❯ IPSW_WATCH_DISCORD_ID=1234 IPSW_WATCH_DISCORD_TOKEN=SECRET ipsw watch security --discord
	`),
	Args:          cobra.NoArgs,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		interval := viper.GetDuration("watch.security.interval")
		if interval < 0 {
			return fmt.Errorf("--interval must be greater than or equal to zero")
		}
		credits := viper.GetStringSlice("watch.security.credit")
		for _, credit := range credits {
			if strings.TrimSpace(credit) == "" {
				return fmt.Errorf("--credit must not be empty")
			}
		}
		if viper.GetBool("watch.discord") {
			if err := validateDiscordFlags(); err != nil {
				return err
			}
		}

		statePath := viper.GetString("watch.security.state")
		if statePath == "" {
			var err error
			statePath, err = watch.DefaultSecurityStatePath()
			if err != nil {
				return err
			}
		} else {
			statePath = expandPath(statePath)
		}
		state, err := watch.LoadSecurityState(statePath)
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		httpClient := download.NewRemoteHTTPClient(
			viper.GetString("watch.security.proxy"),
			viper.GetBool("watch.security.insecure"),
		)
		httpClient.Timeout = securityWatchRequestTimeout

		config := securityWatchConfig{
			statePath: statePath,
			options: watch.SecurityPollOptions{
				NotifyInitial: viper.GetBool("watch.security.notify-initial"),
				Credits:       credits,
			},
			json:    viper.GetBool("watch.security.json"),
			discord: viper.GetBool("watch.discord"),
			discordConfig: announce.DiscordConfig{
				DiscordWebhookID:    viper.GetString("watch.discord-id"),
				DiscordWebhookToken: viper.GetString("watch.discord-token"),
				DiscordColor:        "0xFF3B30",
				DiscordAuthor:       "🛡️ APPLE SECURITY",
				DiscordIconURL:      viper.GetString("watch.discord-icon"),
			},
			httpClient: httpClient,
			output:     cmd.OutOrStdout(),
		}
		client := download.NewSecurityClient(httpClient)

		for {
			nextState, err := pollSecurity(ctx, client, state, config)
			if errors.Is(err, context.Canceled) {
				return nil
			}
			state = nextState
			if interval == 0 {
				return err
			}
			if err != nil {
				log.Errorf("Security watch failed: %v", err)
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

type securityWatchConfig struct {
	statePath     string
	options       watch.SecurityPollOptions
	json          bool
	discord       bool
	discordConfig announce.DiscordConfig
	httpClient    *http.Client
	output        io.Writer
}

// pollSecurity runs one pass and returns the state to carry forward. Advisories
// that could not be fetched are saved unchanged and reported in the error.
func pollSecurity(
	ctx context.Context,
	client *download.SecurityClient,
	state watch.SecurityState,
	config securityWatchConfig,
) (watch.SecurityState, error) {
	poll, err := watch.PollSecurity(ctx, client, state, config.options)
	if err != nil {
		return state, err
	}
	if err := emitSecurityEvents(ctx, poll.Events, config); err != nil {
		return state, err
	}
	if err := watch.SaveSecurityState(config.statePath, poll.State); err != nil {
		return state, err
	}

	log.Infof(
		"Checked %d security advisories: %d event(s), %d not modified, %d without JSON, %d unfetched",
		poll.Checked, len(poll.Events), poll.NotModified, poll.NoJSON, len(poll.Unfetched),
	)
	if poll.Baselined {
		log.Infof("Initialized security watch state with %d advisories at %s", len(poll.State.Advisories), config.statePath)
	}
	return poll.State, poll.UnfetchedError()
}

func emitSecurityEvents(ctx context.Context, events []watch.SecurityEvent, config securityWatchConfig) error {
	switch {
	case len(events) == 0:
		return nil
	case config.discord:
		for _, group := range groupSecurityEvents(events) {
			if err := announce.DiscordContext(ctx, config.httpClient, securityNotification(group), &config.discordConfig); err != nil {
				return fmt.Errorf("discord announce failed: %w", err)
			}
		}
		return nil
	case config.json:
		encoder := json.NewEncoder(config.output)
		for _, event := range events {
			if err := encoder.Encode(event); err != nil {
				return fmt.Errorf("failed to write security event: %w", err)
			}
		}
		return nil
	default:
		messages := make([]string, 0, len(events))
		for _, group := range groupSecurityEvents(events) {
			messages = append(messages, securityNotification(group))
		}
		if _, err := fmt.Fprintln(config.output, strings.Join(messages, "\n\n")); err != nil {
			return fmt.Errorf("failed to write security events: %w", err)
		}
		return nil
	}
}

// groupSecurityEvents splits events into runs that share an advisory. Events
// arrive in index order, so each advisory forms one run.
func groupSecurityEvents(events []watch.SecurityEvent) [][]watch.SecurityEvent {
	var groups [][]watch.SecurityEvent
	start := 0
	for index := 1; index <= len(events); index++ {
		if index == len(events) || events[index].Advisory != events[start].Advisory {
			groups = append(groups, events[start:index])
			start = index
		}
	}
	return groups
}

func securityNotification(events []watch.SecurityEvent) string {
	var out strings.Builder
	first := events[0]
	fmt.Fprintf(&out, "%s (%s)\n%s", first.Name, first.ReleaseDate, first.URL)
	for _, event := range events {
		out.WriteString("\n  ")
		out.WriteString(securityEventLine(event))
	}
	return out.String()
}

var securityEventLabels = map[watch.SecurityEventKind]string{
	watch.SecurityNewAdvisory:        "new",
	watch.SecurityCVEAdded:           "added",
	watch.SecurityCVERemoved:         "removed",
	watch.SecurityCreditsChanged:     "credits",
	watch.SecurityProductsChanged:    "products",
	watch.SecurityImpactChanged:      "impact",
	watch.SecurityDescriptionChanged: "description",
}

func securityEventLine(event watch.SecurityEvent) string {
	var line strings.Builder
	fmt.Fprintf(&line, "%-11s %-16s %s", securityEventLabels[event.Kind], event.CVE, event.Component)
	switch event.Kind {
	case watch.SecurityCreditsChanged, watch.SecurityProductsChanged:
		for _, value := range event.Added {
			fmt.Fprintf(&line, "  +%s", value)
		}
		for _, value := range event.Removed {
			fmt.Fprintf(&line, "  -%s", value)
		}
	case watch.SecurityImpactChanged, watch.SecurityDescriptionChanged:
		fmt.Fprintf(&line, ": %s", event.New)
	case watch.SecurityNewAdvisory, watch.SecurityCVEAdded, watch.SecurityCVERemoved:
		if len(event.Credits) > 0 {
			fmt.Fprintf(&line, " (%s)", strings.Join(event.Credits, "; "))
		}
	}
	return line.String()
}
