package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/blacktop/ipsw/internal/ai/utils"
)

const (
	openrouterChatCompletionsEndpoint = "https://openrouter.ai/api/v1/chat/completions"
	openrouterModelsEndpoint          = "https://openrouter.ai/api/v1/models"
)

// Config holds the configuration for the OpenRouter LLM API client
type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

// OpenRouter represents a client for the OpenRouter API
type OpenRouter struct {
	ctx    context.Context
	conf   *Config
	client *http.Client
	models map[string]string
	apiKey string
}

// chatMessage represents a single message in the conversation
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest is the payload sent to the OpenRouter chat API
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	TopP        float64       `json:"top_p"`
	Stream      bool          `json:"stream"`
}

// chatResponse represents the response from the OpenRouter chat API
type chatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// modelsResponse represents the response from the OpenRouter models API
type modelsResponse struct {
	Data []struct {
		ID              string  `json:"id"`
		Name            string  `json:"name"`
		Description     string  `json:"description"`
		Context_length  int     `json:"context_length"`
		PricePrompt     float64 `json:"pricing.prompt"`
		PriceCompletion float64 `json:"pricing.completion"`
	} `json:"data"`
}

// NewOpenRouter creates a new OpenRouter API client
func NewOpenRouter(ctx context.Context, conf *Config) (*OpenRouter, error) {
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("failed to create OpenRouter client: OPENROUTER_API_KEY environment variable is not set")
	}

	client := &OpenRouter{
		ctx:    ctx,
		conf:   conf,
		client: &http.Client{Timeout: 300 * time.Second},
		models: make(map[string]string),
		apiKey: apiKey,
	}

	return client, nil
}

// Models returns the available models from OpenRouter
func (c *OpenRouter) Models() (map[string]string, error) {
	if len(c.models) > 0 {
		return c.models, nil
	}
	modelsResponse, err := c.getModels()
	if err != nil {
		return nil, fmt.Errorf("openrouter: failed to get models: %w", err)
	}

	// Populate the models map with the model IDs
	for _, model := range modelsResponse.Data {
		c.models[model.Name] = model.ID
	}

	return c.models, nil
}

// SetModel sets the model to use for the OpenRouter client
func (c *OpenRouter) SetModel(model string) error {
	if _, ok := c.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	c.conf.Model = model
	return nil
}

// SetModels sets the available models for the OpenRouter client
func (c *OpenRouter) SetModels(models map[string]string) (map[string]string, error) {
	c.models = models
	return c.models, nil
}

// getModels retrieves the available models from OpenRouter API
func (c *OpenRouter) getModels() (*modelsResponse, error) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", openrouterModelsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setRequestHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response modelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// Chat sends a message to the OpenRouter API and returns the response
func (c *OpenRouter) Chat() (string, error) {
	reqBody := chatRequest{
		Model:       c.models[c.conf.Model],
		Messages:    []chatMessage{{Role: "user", Content: c.conf.Prompt}},
		Temperature: c.conf.Temperature,
		TopP:        c.conf.TopP,
		Stream:      false, // We don't support streaming yet
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(c.ctx, "POST", openrouterChatCompletionsEndpoint, bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	c.setRequestHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}

	return utils.Clean(response.Choices[0].Message.Content), nil
}

// Close implements the ai.AI interface
func (c *OpenRouter) Close() error {
	return nil // No specific resources to close for OpenRouter client
}

// setRequestHeaders sets the common headers for OpenRouter API requests
func (c *OpenRouter) setRequestHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Set HTTP-Referer and X-Title headers only if OPENROUTER_CLIENT_TITLE is set
	if clientTitle := os.Getenv("OPENROUTER_CLIENT_TITLE"); clientTitle != "" {
		req.Header.Set("HTTP-Referer", "https://github.com/blacktop/ipsw")
		req.Header.Set("X-Title", clientTitle)
	}
}
