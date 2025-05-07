package ai

import (
	"context"
	"errors"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ai/anthropic"
	"github.com/blacktop/ipsw/internal/ai/copilot"
	"github.com/blacktop/ipsw/internal/ai/gemini"
	"github.com/blacktop/ipsw/internal/ai/ollama"
	"github.com/blacktop/ipsw/internal/ai/openai"
	db "github.com/blacktop/ipsw/internal/db/ai"
	model "github.com/blacktop/ipsw/internal/model/ai"
	"gorm.io/gorm"
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
	Close() error
}

type Config struct {
	UUID         string
	Provider     string
	Prompt       string
	Model        string
	Temperature  float64
	TopP         float64
	Stream       bool
	DisableCache bool
	Verbose      bool
}

type CachingAI struct {
	ai     AI
	cache  db.CacheDB
	config *Config
}

func (c *CachingAI) Chat() (string, error) {
	chat, err := c.cache.Get(c.config.UUID, c.config.Provider, c.config.Model, c.config.Prompt, c.config.Temperature, c.config.TopP)
	if err == nil && chat != nil {
		return chat.Response, nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Warnf("cache get error: %v", err)
	}

	response, err := c.ai.Chat()
	if err != nil {
		return "", err
	}

	newEntry := &model.ChatResponse{
		UUID:        c.config.UUID,
		Provider:    c.config.Provider,
		LLMModel:    c.config.Model,
		Prompt:      c.config.Prompt,
		Temperature: c.config.Temperature,
		TopP:        c.config.TopP,
		Response:    response,
	}
	if err := c.cache.Set(newEntry); err != nil {
		log.Warnf("cache set error: %v", err)
	}

	return response, nil
}

func (c *CachingAI) Models() []string {
	return c.ai.Models()
}

func (c *CachingAI) SetModel(model string) error {
	c.config.Model = model
	return c.ai.SetModel(model)
}

func (c *CachingAI) Close() error {
	var errs []error
	if c.ai != nil {
		if err := c.ai.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close underlying AI: %w", err))
		}
	}
	if c.cache != nil {
		if err := c.cache.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close AI cache: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors while closing CachingAI: %v", errs)
	}
	return nil
}

func NewAI(ctx context.Context, cfg *Config) (AI, error) {
	var baseAI AI
	var err error

	switch cfg.Provider {
	case "claude":
		baseAI, err = anthropic.NewClaude(ctx, &anthropic.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "copilot":
		baseAI, err = copilot.NewCopilot(ctx, &copilot.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "gemini":
		baseAI, err = gemini.NewGemini(ctx, &gemini.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "ollama":
		baseAI, err = ollama.NewOllama(ctx, &ollama.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "openai":
		baseAI, err = openai.NewOpenAI(ctx, &openai.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	default:
		return nil, fmt.Errorf("unknown AI provider: %s", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create base AI provider %s: %w", cfg.Provider, err)
	}

	if cfg.DisableCache || cfg.Stream {
		log.Warn("AI caching is disabled by config")
		return baseAI, nil
	}

	aiCache, cacheErr := db.NewCacheDB(cfg.Verbose)
	if cacheErr != nil {
		log.Warnf("Failed to initialize AI cache: %v. Proceeding without caching", cacheErr)
		return baseAI, nil
	}

	log.Info("AI caching is enabled")
	return &CachingAI{
		ai:     baseAI,
		cache:  aiCache,
		config: cfg,
	}, nil
}
