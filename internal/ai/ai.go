package ai

import (
	"context"
	"fmt"

	"github.com/blacktop/ipsw/internal/ai/anthropic"
	"github.com/blacktop/ipsw/internal/ai/copilot"
	"github.com/blacktop/ipsw/internal/ai/gemini"
	"github.com/blacktop/ipsw/internal/ai/ollama"
	"github.com/blacktop/ipsw/internal/ai/openai"
)

var Providers = []string{
	"claude",
	"copilot",
	"gemini",
	"ollama",
	"openai",
}

type AI interface {
	Chat() (string, error)
	Models() []string
	SetModel(string) error
}

type Config struct {
	Provider    string
	Prompt      string
	Model       string
	Temperature float64
	TopP        float64
	Stream      bool
}

// NewAI creates a new AI instance based on the provided configuration.
func NewAI(ctx context.Context, cfg *Config) (AI, error) {
	switch cfg.Provider {
	case "claude":
		return anthropic.NewClaude(ctx, &anthropic.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "copilot":
		return copilot.NewCopilot(ctx, &copilot.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "gemini":
		return gemini.NewGemini(ctx, &gemini.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "ollama":
		return ollama.NewOllama(ctx, &ollama.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "openai":
		return openai.NewOpenAI(ctx, &openai.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	default:
		return nil, fmt.Errorf("unknown AI provider: %s", cfg.Provider)
	}
}
