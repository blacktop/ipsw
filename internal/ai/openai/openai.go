package openai

import (
	"cmp"
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/ai/utils"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

type Config struct {
	BaseURL        string  `json:"base_url"`
	APIKey         string  `json:"-"`
	APIKeyEnv      string  `json:"api_key_env"`
	Prompt         string  `json:"prompt"`
	Model          string  `json:"model"`
	Temperature    float64 `json:"temperature"`
	TopP           float64 `json:"top_p"`
	TemperatureSet bool    `json:"-"`
	TopPSet        bool    `json:"-"`
	Stream         bool    `json:"stream"`
}

type OpenAI struct {
	ctx      context.Context
	conf     *Config
	cli      *openai.Client
	models   map[string]string
	cacheKey string
}

func NewOpenAI(ctx context.Context, conf *Config) (*OpenAI, error) {
	baseURL := cmp.Or(conf.BaseURL, os.Getenv("OPENAI_BASE_URL"), "https://api.openai.com/v1")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("OpenAI base URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	baseURL = strings.TrimRight(baseURL, "/")

	apiKey := conf.APIKey
	if apiKey == "" {
		keyEnv := cmp.Or(conf.APIKeyEnv, "OPENAI_API_KEY")
		apiKey = os.Getenv(keyEnv)
		if apiKey == "" && conf.APIKeyEnv != "" {
			return nil, fmt.Errorf("OpenAI API key environment variable %s is not set", keyEnv)
		}
	}

	opts := []option.RequestOption{
		option.WithBaseURL(baseURL),
		option.WithAPIKey(apiKey),
		option.WithRequestTimeout(300 * time.Second),
	}
	if apiKey == "" {
		opts = append(opts, option.WithHeaderDel("Authorization"))
	}
	var organization, project string
	if u.Scheme == "https" && strings.EqualFold(u.Hostname(), "api.openai.com") && (u.Port() == "" || u.Port() == "443") {
		organization = os.Getenv("OPENAI_ORG_ID")
		project = os.Getenv("OPENAI_PROJECT_ID")
	} else {
		// OpenAI account metadata is not intended for third-party endpoints.
		opts = append(opts, option.WithHeaderDel("OpenAI-Organization"), option.WithHeaderDel("OpenAI-Project"))
	}
	cli := openai.NewClient(opts...)
	// Include account identity without persisting credentials or endpoint URLs.
	identity := sha256.New()
	for _, value := range []string{baseURL, apiKey, organization, project} {
		fmt.Fprintf(identity, "%d:%s", len(value), value)
	}
	return &OpenAI{
		ctx:      ctx,
		conf:     conf,
		cli:      &cli,
		cacheKey: fmt.Sprintf("openai-text-chat-v1:%x", identity.Sum(nil)),
	}, nil
}

// CacheKey identifies the effective endpoint, account, and model-list format.
func (c *OpenAI) CacheKey() string {
	return c.cacheKey
}

type modelInfo struct {
	ID                     string   `json:"id"`
	Object                 string   `json:"object"`
	Type                   string   `json:"type"`
	Endpoint               string   `json:"endpoint"`
	SupportedEndpoints     []string `json:"supported_endpoints"`
	SupportedEndpointTypes []string `json:"supported_endpoint_types"`
	Architecture           struct {
		InputModalities  []string `json:"input_modalities"`
		OutputModalities []string `json:"output_modalities"`
	} `json:"architecture"`
}

func isChatEndpoint(endpoint string) bool {
	return endpoint == "/v1/chat/completions" || endpoint == "/chat/completions"
}

func (m modelInfo) canListForTextChat() bool {
	if m.ID == "" || strings.TrimSpace(m.ID) != m.ID || (m.Object != "" && m.Object != "model") {
		return false
	}
	// These extensions are optional. Plain OpenAI model entries contain no
	// capability information, so unknown capabilities remain selectable.
	switch m.Type {
	case "image", "video", "audio", "embedding", "embeddings", "moderation", "rerank":
		return false
	}
	if m.SupportedEndpoints != nil {
		if !slices.ContainsFunc(m.SupportedEndpoints, isChatEndpoint) {
			return false
		}
	} else if m.Endpoint != "" && !isChatEndpoint(m.Endpoint) {
		return false
	}
	return (m.SupportedEndpointTypes == nil || slices.Contains(m.SupportedEndpointTypes, "openai")) &&
		(m.Architecture.InputModalities == nil || slices.Contains(m.Architecture.InputModalities, "text")) &&
		(m.Architecture.OutputModalities == nil || slices.Contains(m.Architecture.OutputModalities, "text"))
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
	if strings.TrimSpace(model) == "" {
		return fmt.Errorf("no model specified")
	}
	c.conf.Model = model
	return nil
}

func (c *OpenAI) SetModels(models map[string]string) (map[string]string, error) {
	c.models = models
	return c.models, nil
}

// Verify checks that the current model configuration is valid
func (c *OpenAI) Verify() error {
	if strings.TrimSpace(c.conf.Model) == "" {
		return fmt.Errorf("no model specified")
	}
	return nil
}

func (c *OpenAI) getModels() error {
	var models struct {
		Data []modelInfo `json:"data"`
	}
	if err := c.cli.Get(c.ctx, "models", nil, &models); err != nil {
		return fmt.Errorf("failed to list models: %w", err)
	}
	c.models = make(map[string]string)
	for _, model := range models.Data {
		if model.canListForTextChat() {
			c.models[model.ID] = model.ID
		}
	}
	if len(c.models) == 0 {
		return fmt.Errorf("no text chat models found; use --dec-model with an explicit model ID")
	}
	return nil
}

func (c *OpenAI) Chat() (string, error) {
	// Verify model configuration before making API call
	if err := c.Verify(); err != nil {
		return "", fmt.Errorf("invalid model configuration: %w", err)
	}

	params := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(c.conf.Prompt),
		},
		Model: c.conf.Model,
	}
	if c.conf.TemperatureSet {
		params.Temperature = openai.Float(c.conf.Temperature)
	}
	if c.conf.TopPSet {
		params.TopP = openai.Float(c.conf.TopP)
	}
	message, err := c.cli.Chat.Completions.New(c.ctx, params)
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
