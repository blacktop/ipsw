package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/utils"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ai/anthropic"
	"github.com/blacktop/ipsw/internal/ai/copilot"
	"github.com/blacktop/ipsw/internal/ai/gemini"
	"github.com/blacktop/ipsw/internal/ai/ollama"
	"github.com/blacktop/ipsw/internal/ai/openai"
	"github.com/blacktop/ipsw/internal/ai/openrouter"
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
	"openrouter",
}

type AI interface {
	Chat() (string, error)
	Models() (map[string]string, error)
	// FIXME: dump convienence method to set models from cache
	SetModels(map[string]string) (map[string]string, error)
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
	MaxRetries   int
	RetryBackoff time.Duration
}

type CachingAI struct {
	ai     AI
	cache  db.CacheDB
	config *Config
}

func (c *CachingAI) Chat() (string, error) {
	if c.cache != nil && !c.config.DisableCache && !c.config.Stream {
		chat, err := c.cache.Get(c.config.UUID, c.config.Provider, c.config.Model, c.config.Prompt, c.config.Temperature, c.config.TopP)
		if err == nil && chat != nil {
			return chat.Response, nil
		}
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, model.ErrNotFound) {
			log.Warnf("cache get error: %v", err)
		}
	}

	response, err := utils.RetryWithResult(c.config.MaxRetries+1, c.config.RetryBackoff, func() (string, error) {
		resp, err := c.ai.Chat()
		if err == nil {
			return resp, nil
		}
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "model not found") ||
			strings.Contains(errStr, "invalid model") ||
			strings.Contains(errStr, "unknown model") ||
			strings.Contains(errStr, "does not exist") ||
			strings.Contains(errStr, "404") ||
			strings.Contains(errStr, "400") {
			log.Warnf("Potential model error detected ('%s'), clearing DB models cache for provider %s", err.Error(), c.config.Provider)
			if c.cache != nil {
				if delErr := c.cache.DeleteProviderModels(c.config.Provider); delErr != nil {
					log.Warnf("Failed to delete provider models from cache for %s: %v", c.config.Provider, delErr)
				}
			}
			// No need to retry if the model is not found
			return "", &utils.StopRetryingError{Err: err}
		}
		return "", err
	})
	if err != nil {
		return "", err
	}

	if c.cache != nil && !c.config.DisableCache && !c.config.Stream {
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
	}

	return response, nil
}

func (c *CachingAI) Models() (map[string]string, error) {
	if c.cache != nil {
		cachedProviderModels, err := c.cache.GetProviderModels(c.config.Provider)
		if err == nil && cachedProviderModels != nil && cachedProviderModels.ModelsJSON != "" {
			var modelsList map[string]string
			if err := json.Unmarshal([]byte(cachedProviderModels.ModelsJSON), &modelsList); err != nil {
				return nil, fmt.Errorf("failed to unmarshal cached models for provider %s: %w", c.config.Provider, err)
			}
			return c.SetModels(modelsList)
		} else if err != nil && !errors.Is(err, model.ErrNotFound) && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed to get cached models for provider %s: %w", c.config.Provider, err)
		}
	}

	log.Debugf("Fetching models for provider %s from underlying AI", c.config.Provider)
	models, err := c.ai.Models()
	if err != nil {
		return nil, fmt.Errorf("failed to get models from underlying AI provider %s: %w", c.config.Provider, err)
	}

	if c.cache != nil && len(models) > 0 {
		modelsJSON, err := json.Marshal(models)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal models for provider %s: %w", c.config.Provider, err)
		} else {
			providerModelsToCache := &model.ProviderModels{
				Provider:   c.config.Provider,
				ModelsJSON: string(modelsJSON),
			}
			if err := c.cache.SetProviderModels(providerModelsToCache); err != nil {
				return nil, fmt.Errorf("failed to set provider models in cache for %s: %w", c.config.Provider, err)
			}
		}
	} else if c.cache != nil && len(models) == 0 {
		log.Debugf("Underlying AI returned no models for provider %s. Caching empty list.", c.config.Provider)
		modelsJSON, _ := json.Marshal([]string{})
		providerModelsToCache := &model.ProviderModels{
			Provider:   c.config.Provider,
			ModelsJSON: string(modelsJSON),
		}
		if err := c.cache.SetProviderModels(providerModelsToCache); err != nil {
			return nil, fmt.Errorf("failed to set provider models in cache for %s: %w", c.config.Provider, err)
		}
	}

	return models, nil
}

func (c *CachingAI) SetModel(model string) error {
	c.config.Model = model
	return c.ai.SetModel(model)
}

func (c *CachingAI) SetModels(models map[string]string) (map[string]string, error) {
	return c.ai.SetModels(models)
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
	var cache db.CacheDB

	if !cfg.DisableCache && !cfg.Stream {
		cache, err = db.NewCacheDB(cfg.Verbose)
		if err != nil {
			log.Warnf("Failed to initialize AI cache: %v. Proceeding without DB caching for tokens/chat.", err)
			cache = nil
		} else {
			log.Info("AI caching is enabled")
		}
	} else {
		log.Warn("AI caching is disabled by config")
		cache = nil
	}

	// Set default values for retry-related fields if not specified
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 0 // Default: no retries
	}

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
			Cache:       cache,
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
	case "openrouter":
		baseAI, err = openrouter.NewOpenRouter(ctx, &openrouter.Config{
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

	ai := &CachingAI{
		ai:     baseAI,
		cache:  cache,
		config: cfg,
	}

	if _, err := ai.Models(); err != nil {
		return nil, fmt.Errorf("failed to prefetch models: %w", err)
	}

	return ai, nil
}
