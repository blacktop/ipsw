package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/apex/log"
)

const discordURL = "https://discord.com/api"

// Config for discord
type Config struct {
	DiscordWebhookID    string `json:"discord_webhook_id"`
	DiscordWebhookToken string `json:"discord_webhook_token"`
	DiscordColor        string `json:"discord_color"`
	DiscordAuthor       string `json:"discord_author"`
	DiscordIconURL      string `json:"discord_icon_url"`
}

type webhookMessageCreate struct {
	Embeds []embed `json:"embeds,omitempty"`
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

// DiscordAnnounce posts a message to a discord webhook
func DiscordAnnounce(msg string, cfg *Config) error {
	log.Infof("posting to discord:\n%s", msg)

	color, err := strconv.Atoi(cfg.DiscordColor)
	if err != nil {
		return fmt.Errorf("discord: %w", err)
	}

	u, err := url.Parse(discordURL)
	if err != nil {
		return fmt.Errorf("DiscordAnnounce faled to parse API url: %w", err)
	}
	u = u.JoinPath("webhooks", cfg.DiscordWebhookID, cfg.DiscordWebhookToken)

	bts, err := json.Marshal(webhookMessageCreate{
		Embeds: []embed{
			{
				Author: &embedAuthor{
					Name:    cfg.DiscordAuthor,
					IconURL: cfg.DiscordIconURL,
				},
				Description: msg,
				Color:       color,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("discord: %w", err)
	}

	resp, err := http.Post(u.String(), "application/json", bytes.NewReader(bts))
	if err != nil {
		return fmt.Errorf("DiscordAnnounce failed to POST: %w", err)
	}

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("DiscordAnnounce got bad status code: %s", resp.Status)
	}

	return nil
}
