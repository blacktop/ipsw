package ollama

import (
	"context"
	"fmt"

	"github.com/blacktop/ipsw/internal/ai/utils"
	"github.com/ollama/ollama/api"
)

type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

type Ollama struct {
	ctx    context.Context
	cfg    *Config
	cli    *api.Client
	models map[string]string
}

func NewOllama(ctx context.Context, cfg *Config) (*Ollama, error) {
	cli, err := api.ClientFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("could not create ollama client: %w", err)
	}
	o := &Ollama{
		ctx: ctx,
		cfg: cfg,
		cli: cli,
	}
	if err := o.getModels(); err != nil {
		return nil, fmt.Errorf("could not get models: %w", err)
	}
	if cfg.Model != "" {
		if _, ok := o.models[cfg.Model]; !ok {
			return nil, fmt.Errorf("model %s not found", cfg.Model)
		}
	}
	if cfg.Temperature < 0 || cfg.Temperature > 1 {
		return nil, fmt.Errorf("temperature must be between 0 and 1")
	}
	if cfg.TopP < 0 || cfg.TopP > 1 {
		return nil, fmt.Errorf("top_p must be between 0 and 1")
	}
	if cfg.Prompt == "" {
		return nil, fmt.Errorf("prompt cannot be empty")
	}
	return o, nil
}

func (o *Ollama) Chat() (string, error) {
	systemMsg := "Provide very brief, concise responses"

	messages := []api.Message{
		{
			Role:    "system",
			Content: systemMsg,
		},
		{
			Role:    "user",
			Content: o.cfg.Prompt,
		},
	}

	var out string

	respFunc := func(cr api.ChatResponse) error {
		out = cr.Message.Content
		return nil
	}

	if err := o.cli.Chat(context.Background(), &api.ChatRequest{
		Model:    o.cfg.Model,
		Messages: messages,
		Stream:   new(bool),
	}, respFunc); err != nil {
		return "", fmt.Errorf("failed to chat with ollama: %w", err)
	}

	if out == "" {
		return "", fmt.Errorf("ollama returned empty response")
	}

	return utils.Clean(out), nil
}

func (o *Ollama) Models() (map[string]string, error) {
	if len(o.models) > 0 {
		return o.models, nil
	}
	if err := o.getModels(); err != nil {
		return nil, fmt.Errorf("ollama: failed to get models: %w", err)
	}
	return o.models, nil
}

func (o *Ollama) SetModel(model string) error {
	if _, ok := o.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	o.cfg.Model = model
	return nil
}

func (o *Ollama) SetModels(models map[string]string) (map[string]string, error) {
	return o.models, nil // cache is not used for local models
}

func (o *Ollama) getModels() error {
	o.models = make(map[string]string)

	models, err := o.cli.List(o.ctx)
	if err != nil {
		return fmt.Errorf("failed to get models: %w", err)
	}
	for _, model := range models.Models {
		o.models[model.Name] = model.Model
	}

	return nil
}

// Close implements the ai.AI interface.
func (o *Ollama) Close() error {
	return nil // No specific resources to close for Ollama client
}
