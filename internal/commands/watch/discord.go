package watch

import (
	"fmt"
	"strconv"

	"github.com/apex/log"
	"github.com/disgoorg/disgo/discord"
	"github.com/disgoorg/disgo/webhook"
	"github.com/disgoorg/snowflake/v2"
)

// Config for discord
type Config struct {
	DiscordWebhookID    string `json:"discord_webhook_id"`
	DiscordWebhookToken string `json:"discord_webhook_token"`
	DiscordColor        string `json:"discord_color"`
	DiscordAuthor       string `json:"discord_author"`
	DiscordIconURL      string `json:"discord_icon_url"`
}

// DiscordAnnounce posts a message to a discord webhook
func DiscordAnnounce(msg string, cfg *Config) error {
	log.Infof("posting to discord:\n%s", msg)

	webhookID, err := snowflake.Parse(cfg.DiscordWebhookID)
	if err != nil {
		return fmt.Errorf("discord: %w", err)
	}

	color, err := strconv.Atoi(cfg.DiscordColor)
	if err != nil {
		return fmt.Errorf("discord: %w", err)
	}

	if _, err = webhook.New(webhookID, cfg.DiscordWebhookToken).CreateMessage(discord.WebhookMessageCreate{
		Embeds: []discord.Embed{
			{
				Author: &discord.EmbedAuthor{
					Name:    cfg.DiscordAuthor,
					IconURL: cfg.DiscordIconURL,
				},
				Description: msg,
				Color:       color,
			},
		},
	}); err != nil {
		return fmt.Errorf("discord: %w", err)
	}

	return nil
}
