package gemini

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/blacktop/ipsw/internal/ai/utils"
	"google.golang.org/genai"
)

type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

type Gemini struct {
	ctx    context.Context
	conf   *Config
	cli    *genai.Client
	models map[string]string
}

func NewGemini(ctx context.Context, conf *Config) (*Gemini, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("failed to create google gemini client: GEMINI_API_KEY environment variable is not set")
	}
	cli, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create google gemini client: %w", err)
	}
	gemini := &Gemini{
		ctx:  ctx,
		conf: conf,
		cli:  cli,
	}
	return gemini, nil
}

func (c *Gemini) Models() (map[string]string, error) {
	if len(c.models) > 0 {
		return c.models, nil
	}
	if err := c.getModels(); err != nil {
		return nil, fmt.Errorf("gemini: failed to get models: %w", err)
	}
	return c.models, nil
}

func (c *Gemini) SetModel(model string) error {
	if _, ok := c.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	c.conf.Model = model
	return nil
}

func (c *Gemini) SetModels(models map[string]string) (map[string]string, error) {
	c.models = models
	return c.models, nil
}

func (c *Gemini) getModels() error {
	models, err := c.cli.Models.List(c.ctx, &genai.ListModelsConfig{})
	if err != nil {
		return fmt.Errorf("failed to list models: %w", err)
	}
	c.models = make(map[string]string)
	for _, model := range models.Items {
		if slices.Contains(model.SupportedActions, "generateContent") {
			c.models[model.DisplayName] = model.Name
		}
	}
	if len(c.models) == 0 {
		return fmt.Errorf("no models found")
	}
	return nil
}

func (c *Gemini) Chat() (string, error) {
	chat, err := c.cli.Chats.Create(c.ctx,
		c.models[c.conf.Model],
		&genai.GenerateContentConfig{
			Temperature: genai.Ptr(float32(c.conf.Temperature)),
			TopP:        genai.Ptr(float32(c.conf.TopP)),
		},
		nil, // history
	)
	if err != nil {
		return "", fmt.Errorf("failed to create message: %w", err)
	}

	message, err := chat.SendMessage(c.ctx, genai.Part{Text: c.conf.Prompt})
	if err != nil {
		return "", fmt.Errorf("failed to send message: %w", err)
	}

	return utils.Clean(message.Text()), nil
}

// Close implements the ai.AI interface.
func (g *Gemini) Close() error {
	return nil // No specific resources to close for Gemini client
}
