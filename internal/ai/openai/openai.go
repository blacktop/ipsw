package openai

import (
	"context"
	"fmt"

	"github.com/blacktop/ipsw/internal/ai/utils"
	"github.com/openai/openai-go"
)

type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

type OpenAI struct {
	ctx    context.Context
	conf   *Config
	cli    *openai.Client
	models map[string]string
}

func NewOpenAI(ctx context.Context, conf *Config) (*OpenAI, error) {
	cli := openai.NewClient()
	openai := &OpenAI{
		ctx:  ctx,
		conf: conf,
		cli:  &cli,
	}
	return openai, nil
}

func (c *OpenAI) Models() (map[string]string, error) {
	if len(c.models) > 0 {
		return c.models, nil
	}
	if err := c.getModels(); err != nil {
		return nil, fmt.Errorf("openai: failed to get models: %w", err)
	}
	return c.models, nil
}

func (c *OpenAI) SetModel(model string) error {
	if _, ok := c.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	c.conf.Model = model
	return nil
}

func (c *OpenAI) SetModels(models map[string]string) (map[string]string, error) {
	c.models = models
	return c.models, nil
}

func (c *OpenAI) getModels() error {
	models, err := c.cli.Models.List(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to list models: %w", err)
	}
	c.models = make(map[string]string)
	for _, model := range models.Data {
		c.models[model.ID] = model.ID
	}
	if len(c.models) == 0 {
		return fmt.Errorf("no models found")
	}
	return nil
}

func (c *OpenAI) Chat() (string, error) {
	message, err := c.cli.Chat.Completions.New(c.ctx, openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(c.conf.Prompt),
		},
		Model:       c.models[c.conf.Model],
		Temperature: openai.Float(c.conf.Temperature),
		TopP:        openai.Float(c.conf.TopP),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create message: %w", err)
	}

	if len(message.Choices) == 0 {
		return "", fmt.Errorf("no content returned from message")
	}

	return utils.Clean(message.Choices[0].Message.Content), nil
}

// Close implements the ai.AI interface.
func (o *OpenAI) Close() error {
	return nil // No specific resources to close for OpenAI client
}
