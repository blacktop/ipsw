package announce

import (
	"context"
	"fmt"

	"github.com/apex/log"
	"github.com/mattn/go-mastodon"
)

type MastodonConfig struct {
	Server       string `json:"server,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
}

func Mastodon(msg string, cfg *MastodonConfig) error {
	log.Infof("posting: '%s'", msg)

	client := mastodon.NewClient(&mastodon.Config{
		Server:       cfg.Server,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		AccessToken:  cfg.AccessToken,
	})

	if _, err := client.PostStatus(context.Background(), &mastodon.Toot{
		Status: msg,
	}); err != nil {
		return fmt.Errorf("failed to post to mastodon: %w", err)
	}
	return nil
}
