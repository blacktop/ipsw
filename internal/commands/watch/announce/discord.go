package announce

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/apex/log"
)

const discordURL = "https://discord.com/api"

// DiscordConfig for discord
type DiscordConfig struct {
	DiscordWebhookID    string `json:"discord_webhook_id"`
	DiscordWebhookToken string `json:"discord_webhook_token"`
	DiscordColor        string `json:"discord_color"`
	DiscordAuthor       string `json:"discord_author"`
	DiscordIconURL      string `json:"discord_icon_url"`
}

type webhookMessageCreate struct {
	Content         string           `json:"content,omitempty"`
	Embeds          []embed          `json:"embeds,omitempty"`
	AllowedMentions *allowedMentions `json:"allowed_mentions,omitempty"`
	Username        string           `json:"username,omitempty"`
	AvatarURL       string           `json:"avatar_url,omitempty"`
}

type embed struct {
	Description string       `json:"description,omitempty"`
	Color       int          `json:"color,omitempty"`
	Author      *embedAuthor `json:"author,omitempty"`
}

type embedAuthor struct {
	Name    string `json:"name,omitempty"`
	IconURL string `json:"icon_url,omitempty"`
}

type allowedMentions struct {
	Parse []string `json:"parse"`
}

func clampString(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	switch {
	case max <= 1:
		return ""
	case max <= 3:
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func parseColor(colorStr string) (int, error) {
	if colorStr == "" {
		return 0x5865F2, nil // Discord blurple default
	}
	val, err := strconv.ParseInt(strings.TrimSpace(colorStr), 0, 32) // base 0 allows 0x/0 prefixes
	if err != nil {
		return 0, fmt.Errorf("discord: %w", err)
	}
	if val < 0 || val > 0xFFFFFF {
		return 0, fmt.Errorf("discord: color out of range")
	}
	return int(val), nil
}

// Discord posts a message to a discord webhook
func Discord(msg string, cfg *DiscordConfig) error {
	log.Infof("posting to discord:\n%s", msg)

	color, err := parseColor(cfg.DiscordColor)
	if err != nil {
		return err
	}

	description := strings.TrimSpace(msg)
	if description == "" {
		description = "(empty message)"
	}
	description = clampString(description, 4096)                     // Discord embed description limit
	author := clampString(strings.TrimSpace(cfg.DiscordAuthor), 256) // author name limit
	content := clampString(description, 2000)                        // message content limit

	u, err := url.Parse(discordURL)
	if err != nil {
		return fmt.Errorf("DiscordAnnounce failed to parse API url: %w", err)
	}
	u = u.JoinPath("webhooks", cfg.DiscordWebhookID, cfg.DiscordWebhookToken)

	bts, err := json.Marshal(webhookMessageCreate{
		Content: content,
		Embeds: []embed{
			{
				Author: &embedAuthor{
					Name:    author,
					IconURL: cfg.DiscordIconURL,
				},
				Description: description,
				Color:       color,
			},
		},
		AllowedMentions: &allowedMentions{Parse: []string{}}, // avoid accidental pings
	})
	if err != nil {
		return fmt.Errorf("discord: %w", err)
	}

	resp, err := http.Post(u.String(), "application/json", bytes.NewReader(bts))
	if err != nil {
		return fmt.Errorf("DiscordAnnounce failed to POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("DiscordAnnounce got bad status code: %s (failed to read body: %w)", resp.Status, err)
		}
		return fmt.Errorf("DiscordAnnounce got bad status code: %s (response: %s)", resp.Status, strings.TrimSpace(string(body)))
	}

	return nil
}
