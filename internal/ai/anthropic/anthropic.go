package anthropic

import (
	"context"
	"fmt"
	"sort"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/blacktop/ipsw/internal/ai/utils"
)

type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

type Claude struct {
	ctx    context.Context
	conf   *Config
	cli    *anthropic.Client
	models map[string]string
}

func NewClaude(ctx context.Context, conf *Config) (*Claude, error) {
	cli := anthropic.NewClient()
	claude := &Claude{
		ctx:  ctx,
		conf: conf,
		cli:  &cli,
	}
	if err := claude.getModels(); err != nil {
		return nil, fmt.Errorf("failed to get models: %w", err)
	}
	return claude, nil
}

func (c *Claude) Models() []string {
	modelList := make([]string, 0, len(c.models))
	for model := range c.models {
		modelList = append(modelList, model)
	}
	sort.Strings(modelList)
	return modelList
}

func (c *Claude) SetModel(model string) error {
	if _, ok := c.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	c.conf.Model = model
	return nil
}

func (c *Claude) getModels() error {
	models, err := c.cli.Models.List(c.ctx, anthropic.ModelListParams{})
	if err != nil {
		return fmt.Errorf("failed to list models: %w", err)
	}
	c.models = make(map[string]string)
	for _, model := range models.Data {
		c.models[model.DisplayName] = model.ID
	}
	if len(c.models) == 0 {
		return fmt.Errorf("no models found")
	}
	return nil
}

func (c *Claude) Chat() (string, error) {
	message, err := c.cli.Messages.New(c.ctx, anthropic.MessageNewParams{
		MaxTokens: 1024,
		Messages: []anthropic.MessageParam{{
			Role: anthropic.MessageParamRoleUser,
			Content: []anthropic.ContentBlockParamUnion{{
				OfRequestTextBlock: &anthropic.TextBlockParam{Text: c.conf.Prompt},
			}},
		}},
		Model:       c.models[c.conf.Model],
		Temperature: anthropic.Float(c.conf.Temperature),
		TopP:        anthropic.Float(c.conf.TopP),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create message: %w", err)
	}

	if len(message.Content) == 0 {
		return "", fmt.Errorf("no content returned from message")
	}

	return utils.Clean(message.Content[0].Text), nil
}

// Close implements the ai.AI interface.
func (c *Claude) Close() error {
	return nil // No specific resources to close for Claude client
}
