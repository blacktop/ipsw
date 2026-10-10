package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/utils"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ai/acp"
	"github.com/blacktop/ipsw/internal/ai/anthropic"
	"github.com/blacktop/ipsw/internal/ai/gemini"
	"github.com/blacktop/ipsw/internal/ai/ollama"
	"github.com/blacktop/ipsw/internal/ai/openai"
	"github.com/blacktop/ipsw/internal/ai/openrouter"
	"github.com/blacktop/ipsw/internal/ai/orcarouter"
	db "github.com/blacktop/ipsw/internal/db/ai"
	model "github.com/blacktop/ipsw/internal/model/ai"
	"gorm.io/gorm"
)

var Providers = []string{
	"anthropic",
	"claude",
	"copilot",
	"codex",
	"gemini",
	"google",
	"ollama",
	"openai",
	"openai-compatible",
	"openrouter",
	"orcarouter",
}

var ProviderAliases = map[string]string{
	"openai-compatible": "openai",
	// Legacy ACP provider names
	"claude-code-acp": "claude",
	"codex-acp":       "codex",
	"gemini-acp":      "gemini",
	// Legacy API provider names
	"claude": "claude", // canonical (ACP)
	"gemini": "gemini", // canonical (ACP)
	// Explicit API aliases
	"claude-api": "anthropic",
	"gemini-api": "google",
}

func NormalizeProvider(provider string) string {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return provider
	}
	if canonical, ok := ProviderAliases[provider]; ok {
		return canonical
	}
	return provider
}

func IsValidProvider(provider string) bool {
	return slices.Contains(Providers, NormalizeProvider(provider))
}

type AI interface {
	Chat() (string, error)
	Models() (map[string]string, error)
	// FIXME: dump convienence method to set models from cache
	SetModels(map[string]string) (map[string]string, error)
	SetModel(string) error
	Verify() error
	Close() error
}

type Config struct {
	UUID           string
	Provider       string
	BaseURL        string
	APIKey         string
	APIKeyEnv      string
	Prompt         string
	Model          string
	Temperature    float64
	TopP           float64
	TemperatureSet bool
	TopPSet        bool
	Stream         bool
	DisableCache   bool
	Verbose        bool
	MaxRetries     int
	RetryBackoff   time.Duration
}

type CachingAI struct {
	ai             AI
	cache          db.CacheDB
	config         *Config
	chatCacheKey   string
	modelsCacheKey string
}

// Version the OrcaRouter model cache because older entries contain models for
// endpoints that the text decompiler cannot use.
const orcarouterTextChatModelsCacheKey = "orcarouter-text-chat-v1"

func modelsCacheKeyForProvider(provider string) string {
	if provider == "orcarouter" {
		return orcarouterTextChatModelsCacheKey
	}
	return provider
}

func (c *CachingAI) Chat() (string, error) {
	providerKey := c.chatCacheKey
	if providerKey == "" {
		providerKey = c.config.Provider
	}
	if c.cache != nil && !c.config.DisableCache && !c.config.Stream {
		chat, err := c.cache.Get(c.config.UUID, providerKey, c.config.Model, c.config.Prompt, c.config.Temperature, c.config.TopP)
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
				if delErr := c.cache.DeleteProviderModels(c.modelsCacheKey); delErr != nil {
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
			Provider:    providerKey,
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
		cachedProviderModels, err := c.cache.GetProviderModels(c.modelsCacheKey)
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
				Provider:   c.modelsCacheKey,
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
			Provider:   c.modelsCacheKey,
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

func (c *CachingAI) Verify() error {
	return c.ai.Verify()
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
	var chatCacheKey, modelsCacheKey string

	cfg.Provider = NormalizeProvider(cfg.Provider)

	// Set default values for retry-related fields if not specified
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 0 // Default: no retries
	}

	switch cfg.Provider {
	case "claude":
		baseAI, err = acp.New(ctx, &acp.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
			Command:     "npx",
			Args:        []string{"-y", "@zed-industries/claude-code-acp@latest"},
			Verbose:     cfg.Verbose,
		})
	case "anthropic":
		baseAI, err = anthropic.NewClaude(ctx, &anthropic.Config{
			Prompt:         cfg.Prompt,
			Model:          cfg.Model,
			Temperature:    cfg.Temperature,
			TemperatureSet: cfg.TemperatureSet,
			TopP:           cfg.TopP,
			TopPSet:        cfg.TopPSet,
			Stream:         cfg.Stream,
		})
	case "copilot":
		baseAI, err = acp.New(ctx, &acp.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
			Command:     "copilot",
			Args: []string{
				"--acp",
				"--stdio",
				"--available-tools=",
				"--disable-builtin-mcps",
				"--no-ask-user",
				"--no-auto-update",
				"--no-custom-instructions",
				"--no-remote",
				"--no-remote-export",
				"--log-level=none",
			},
			Verbose: cfg.Verbose,
		})
		// Do not reuse model IDs or chat responses cached by the retired
		// editor-token-backed Copilot implementation.
		cfg.Provider = "copilot-acp"
	case "codex":
		baseAI, err = acp.New(ctx, &acp.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
			Command:     "npx",
			Args:        []string{"-y", "@zed-industries/codex-acp@latest"},
			Verbose:     cfg.Verbose,
		})
	case "gemini":
		baseAI, err = acp.New(ctx, &acp.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
			Command:     "npx",
			Args:        []string{"-y", "@google/gemini-cli@latest", "--experimental-acp"},
			Verbose:     cfg.Verbose,
		})
	case "google":
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
		var client *openai.OpenAI
		client, err = openai.NewOpenAI(ctx, &openai.Config{
			BaseURL:        cfg.BaseURL,
			APIKey:         cfg.APIKey,
			APIKeyEnv:      cfg.APIKeyEnv,
			Prompt:         cfg.Prompt,
			Model:          cfg.Model,
			Temperature:    cfg.Temperature,
			TemperatureSet: cfg.TemperatureSet,
			TopP:           cfg.TopP,
			TopPSet:        cfg.TopPSet,
			Stream:         cfg.Stream,
		})
		if err == nil {
			baseAI = client
			modelsCacheKey = client.CacheKey()
			var temperature, topP string
			if cfg.TemperatureSet {
				temperature = strconv.FormatFloat(cfg.Temperature, 'g', -1, 64)
			}
			if cfg.TopPSet {
				topP = strconv.FormatFloat(cfg.TopP, 'g', -1, 64)
			}
			// The DB's struct-based query omits zero values, so retain the
			// actual optional controls in this provider's cache identity.
			chatCacheKey = fmt.Sprintf("%s:temperature=%s:top-p=%s", modelsCacheKey, temperature, topP)
		}
	case "openrouter":
		baseAI, err = openrouter.NewOpenRouter(ctx, &openrouter.Config{
			Prompt:      cfg.Prompt,
			Model:       cfg.Model,
			Temperature: cfg.Temperature,
			TopP:        cfg.TopP,
			Stream:      cfg.Stream,
		})
	case "orcarouter":
		baseAI, err = orcarouter.NewOrcaRouter(ctx, &orcarouter.Config{
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
	if modelsCacheKey == "" {
		modelsCacheKey = modelsCacheKeyForProvider(cfg.Provider)
	}
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
	}

	ai := &CachingAI{
		ai:             baseAI,
		cache:          cache,
		config:         cfg,
		chatCacheKey:   chatCacheKey,
		modelsCacheKey: modelsCacheKey,
	}

	// Compatible endpoints may support chat without offering a model catalog.
	if cfg.Provider != "openai" || cfg.Model == "" {
		if _, err := ai.Models(); err != nil {
			if closeErr := ai.Close(); closeErr != nil {
				log.Warnf("Failed to close AI client: %v", closeErr)
			}
			return nil, fmt.Errorf("failed to prefetch models: %w", err)
		}
	}

	return ai, nil
}
