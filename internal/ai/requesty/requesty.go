package requesty

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
	requestyChatCompletionsEndpoint = "https://router.requesty.ai/v1/chat/completions"
	requestyModelsEndpoint          = "https://router.requesty.ai/v1/models"
)

// Config holds the configuration for the Requesty LLM API client
type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

// Requesty represents a client for the Requesty API
type Requesty struct {
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

// chatRequest is the payload sent to the Requesty chat API
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	TopP        float64       `json:"top_p"`
	Stream      bool          `json:"stream"`
}

// chatResponse represents the response from the Requesty chat API
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

// modelsResponse represents the response from the Requesty models API
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

// NewRequesty creates a new Requesty API client
func NewRequesty(ctx context.Context, conf *Config) (*Requesty, error) {
	apiKey := os.Getenv("REQUESTY_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("failed to create Requesty client: REQUESTY_API_KEY environment variable is not set")
	}

	client := &Requesty{
		ctx:    ctx,
		conf:   conf,
		client: &http.Client{Timeout: 300 * time.Second},
		models: make(map[string]string),
		apiKey: apiKey,
	}

	return client, nil
}

// Models returns the available models from Requesty
func (c *Requesty) Models() (map[string]string, error) {
	if len(c.models) > 0 {
		return c.models, nil
	}
	modelsResponse, err := c.getModels()
	if err != nil {
		return nil, fmt.Errorf("requesty: failed to get models: %w", err)
	}

	// Populate the models map with the model IDs. Requesty's /v1/models
	// returns OpenAI-shaped entries that are keyed by "id" (e.g.
	// "openai/gpt-4o-mini") and may omit a separate display "name", so fall
	// back to the ID when no name is provided.
	for _, model := range modelsResponse.Data {
		key := model.Name
		if key == "" {
			key = model.ID
		}
		c.models[key] = model.ID
	}

	return c.models, nil
}

// SetModel sets the model to use for the Requesty client
func (c *Requesty) SetModel(model string) error {
	if _, ok := c.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	c.conf.Model = model
	return nil
}

// SetModels sets the available models for the Requesty client
func (c *Requesty) SetModels(models map[string]string) (map[string]string, error) {
	c.models = models
	return c.models, nil
}

// Verify checks that the current model configuration is valid
func (c *Requesty) Verify() error {
	if c.conf.Model == "" {
		return fmt.Errorf("no model specified")
	}
	if len(c.models) == 0 {
		if _, err := c.Models(); err != nil {
			return fmt.Errorf("failed to fetch models: %v", err)
		}
	}
	modelID, ok := c.models[c.conf.Model]
	if !ok {
		// Model not found in cache, try refreshing the models list
		c.models = make(map[string]string) // Clear cache to force refresh
		if _, err := c.Models(); err != nil {
			return fmt.Errorf("failed to fetch models: %v", err)
		}
		// Check again after refresh
		modelID, ok = c.models[c.conf.Model]
		if !ok {
			return fmt.Errorf("model '%s' not found in available models", c.conf.Model)
		}
	}
	if modelID == "" {
		return fmt.Errorf("model '%s' has empty ID", c.conf.Model)
	}
	return nil
}

// getModels retrieves the available models from Requesty API
func (c *Requesty) getModels() (*modelsResponse, error) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", requestyModelsEndpoint, nil)
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

// Chat sends a message to the Requesty API and returns the response
func (c *Requesty) Chat() (string, error) {
	// Verify model configuration before making API call
	if err := c.Verify(); err != nil {
		return "", fmt.Errorf("invalid model configuration: %w", err)
	}

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

	req, err := http.NewRequestWithContext(c.ctx, "POST", requestyChatCompletionsEndpoint, bytes.NewBuffer(data))
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
func (c *Requesty) Close() error {
	return nil // No specific resources to close for Requesty client
}

// setRequestHeaders sets the common headers for Requesty API requests
func (c *Requesty) setRequestHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Set HTTP-Referer and X-Title headers only if REQUESTY_CLIENT_TITLE is set
	if clientTitle := os.Getenv("REQUESTY_CLIENT_TITLE"); clientTitle != "" {
		req.Header.Set("HTTP-Referer", "https://github.com/blacktop/ipsw")
		req.Header.Set("X-Title", clientTitle)
	}
}
