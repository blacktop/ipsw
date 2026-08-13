package orcarouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/ai/utils"
)

const orcarouterBaseURL = "https://api.orcarouter.ai/v1"

// Config holds the configuration for the OrcaRouter LLM API client
type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

// OrcaRouter represents a client for the OrcaRouter API
type OrcaRouter struct {
	ctx     context.Context
	conf    *Config
	client  *http.Client
	models  map[string]string
	apiKey  string
	baseURL string
}

// chatMessage represents a single message in the conversation
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest is the payload sent to the OrcaRouter chat API
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	TopP        float64       `json:"top_p"`
	Stream      bool          `json:"stream"`
}

// chatResponse represents the response from the OrcaRouter chat API
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

type modelArchitecture struct {
	InputModalities  []string `json:"input_modalities"`
	OutputModalities []string `json:"output_modalities"`
}

type modelInfo struct {
	ID                     string            `json:"id"`
	Object                 string            `json:"object"`
	SupportedEndpointTypes []string          `json:"supported_endpoint_types"`
	Architecture           modelArchitecture `json:"architecture"`
}

// modelsResponse represents the response from the OrcaRouter models API.
// It follows the OpenAI-compatible shape: model IDs are the lookup keys.
type modelsResponse struct {
	Data []modelInfo `json:"data"`
}

// NewOrcaRouter creates a new OrcaRouter API client
func NewOrcaRouter(ctx context.Context, conf *Config) (*OrcaRouter, error) {
	return newOrcaRouter(
		ctx,
		conf,
		os.Getenv("ORCAROUTER_API_KEY"),
		orcarouterBaseURL,
		&http.Client{Timeout: 300 * time.Second},
	)
}

func newOrcaRouter(ctx context.Context, conf *Config, apiKey, baseURL string, httpClient *http.Client) (*OrcaRouter, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("failed to create OrcaRouter client: ORCAROUTER_API_KEY environment variable is not set")
	}

	baseURL = strings.TrimRight(baseURL, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 300 * time.Second}
	}

	return &OrcaRouter{
		ctx:     ctx,
		conf:    conf,
		client:  httpClient,
		models:  make(map[string]string),
		apiKey:  apiKey,
		baseURL: baseURL,
	}, nil
}

// Models returns the available models from OrcaRouter
func (c *OrcaRouter) Models() (map[string]string, error) {
	if len(c.models) > 0 {
		return c.models, nil
	}
	response, err := c.getModels()
	if err != nil {
		return nil, fmt.Errorf("orcarouter: failed to get models: %w", err)
	}

	// The catalog includes models for image, audio, video, and native-only APIs.
	// The decompiler requires OpenAI-compatible text input and text output.
	for _, model := range response.Data {
		if supportsTextChat(model) {
			c.models[model.ID] = model.ID
		}
	}
	if len(c.models) == 0 {
		return nil, fmt.Errorf("orcarouter: no text chat models found")
	}

	return c.models, nil
}

func supportsTextChat(model modelInfo) bool {
	return model.Object == "model" &&
		model.ID != "" &&
		model.ID == strings.TrimSpace(model.ID) &&
		slices.Contains(model.SupportedEndpointTypes, "openai") &&
		slices.Contains(model.Architecture.InputModalities, "text") &&
		slices.Contains(model.Architecture.OutputModalities, "text")
}

// SetModel sets the model to use for the OrcaRouter client
func (c *OrcaRouter) SetModel(model string) error {
	if _, ok := c.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	c.conf.Model = model
	return nil
}

// SetModels sets the available models for the OrcaRouter client
func (c *OrcaRouter) SetModels(models map[string]string) (map[string]string, error) {
	c.models = models
	return c.models, nil
}

// Verify checks that the current model configuration is valid
func (c *OrcaRouter) Verify() error {
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

// getModels retrieves the available models from OrcaRouter API
func (c *OrcaRouter) getModels() (*modelsResponse, error) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", c.baseURL+"/models", nil)
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

// Chat sends a message to the OrcaRouter API and returns the response
func (c *OrcaRouter) Chat() (string, error) {
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

	req, err := http.NewRequestWithContext(c.ctx, "POST", c.baseURL+"/chat/completions", bytes.NewBuffer(data))
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
func (c *OrcaRouter) Close() error {
	return nil // No specific resources to close for OrcaRouter client
}

// setRequestHeaders sets the common headers for OrcaRouter API requests
func (c *OrcaRouter) setRequestHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}
