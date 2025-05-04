package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	copilotChatAuthURL   = "https://api.github.com/copilot_internal/v2/token"
	copilotEditorVersion = "vscode/1.95.3"
	copilotUserAgent     = "curl/7.81.0" // Necessay to bypass the user-agent check
)

var CopilotModels = []string{
	"Claude 3.5 Sonnet",
	"Claude 3.7 Sonnet",
	"Claude 3.7 Sonnet Thinking",
	"Gemini 2.0 Flash",
	"Gemini 2.5 Pro (Preview)",
	"o4-mini (Preview)",
	"GPT-4.1 (Preview)",
}

// tokenResponse matches the GitHub auth endpoint
type tokenResponse struct {
	AnnotationsEnabled   bool `json:"annotations_enabled"`
	ChatEnabled          bool `json:"chat_enabled"`
	ChatJetbrainsEnabled bool `json:"chat_jetbrains_enabled"`
	CodeQuoteEnabled     bool `json:"code_quote_enabled"`
	CodeReviewEnabled    bool `json:"code_review_enabled"`
	Codesearch           bool `json:"codesearch"`
	CopilotignoreEnabled bool `json:"copilotignore_enabled"`
	Endpoints            struct {
		API           string `json:"api"`
		OriginTracker string `json:"origin-tracker"`
		Proxy         string `json:"proxy"`
		Telemetry     string `json:"telemetry"`
	} `json:"endpoints"`
	ExpiresAt             int64       `json:"expires_at"`
	Individual            bool        `json:"individual"`
	LimitedUserQuotas     interface{} `json:"limited_user_quotas"`
	LimitedUserResetDate  interface{} `json:"limited_user_reset_date"`
	Prompt8K              bool        `json:"prompt_8k"`
	PublicSuggestions     string      `json:"public_suggestions"`
	RefreshIn             int         `json:"refresh_in"`
	SKU                   string      `json:"sku"`
	SnippyLoadTestEnabled bool        `json:"snippy_load_test_enabled"`
	Telemetry             string      `json:"telemetry"`
	Token                 string      `json:"token"`
	TrackingID            string      `json:"tracking_id"`
	VscElectronFetcherV2  bool        `json:"vsc_electron_fetcher_v2"`
	Xcode                 bool        `json:"xcode"`
	XcodeChat             bool        `json:"xcode_chat"`
	ErrorDetails          *struct {
		URL            string `json:"url,omitempty"`
		Message        string `json:"message,omitempty"`
		Title          string `json:"title,omitempty"`
		NotificationID string `json:"notification_id,omitempty"`
	} `json:"error_details,omitempty"`
}

type modelsResponse struct {
	Data []struct {
		Capabilities struct {
			Family string `json:"family"`
			Limits struct {
				MaxContextWindowTokens int `json:"max_context_window_tokens"`
				MaxOutputTokens        int `json:"max_output_tokens"`
				MaxPromptTokens        int `json:"max_prompt_tokens"`
			} `json:"limits"`
			Object   string `json:"object"`
			Supports struct {
				Streaming bool `json:"streaming"`
				ToolCalls bool `json:"tool_calls"`
			} `json:"supports"`
			Tokenizer string `json:"tokenizer"`
			Type      string `json:"type"`
		} `json:"capabilities"`
		ID                 string `json:"id"`
		ModelPickerEnabled bool   `json:"model_picker_enabled"`
		Name               string `json:"name"`
		Object             string `json:"object"`
		Preview            bool   `json:"preview"`
		Vendor             string `json:"vendor"`
		Version            string `json:"version"`
		Policy             struct {
			State string `json:"state"`
			Terms string `json:"terms"`
		} `json:"policy,omitempty"`
	} `json:"data"`
	Object string `json:"object"`
}

// chatMessage represents a single message in the conversation
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest is the payload sent to the chat API
type chatRequest struct {
	Intent      bool          `json:"intent"`
	N           int           `json:"n"`
	Stream      bool          `json:"stream"`
	Temperature float64       `json:"temperature"`
	TopP        float64       `json:"top_p"`
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
}

// responseEvent models both streaming and non‐streaming replies
type responseEvent struct {
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Index        int    `json:"index"`
		Delta        *struct {
			Content *string `json:"content"`
		} `json:"delta,omitempty"`
		Message *struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message,omitempty"`
	} `json:"choices"`
	Created int64  `json:"created"`
	ID      string `json:"id"`
}

type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`
}

type Copilot struct {
	ctx    context.Context
	conf   *Config
	token  *tokenResponse
	models map[string]string
}

func NewCopilot(ctx context.Context, conf *Config) (*Copilot, error) {
	c := &Copilot{
		ctx:    ctx,
		conf:   conf,
		models: make(map[string]string),
	}
	oauth, err := readLocalToken()
	if err != nil {
		return nil, fmt.Errorf("failed to read local github copilot token: %v", err)
	}
	c.token, err = getAPIToken(ctx, oauth)
	if err != nil {
		return nil, fmt.Errorf("failed to get github copilot API token: %v", err)
	}
	if time.Now().After(time.Unix(c.token.ExpiresAt, 0)) {
		expiresAt := time.Unix(c.token.ExpiresAt, 0).Format(time.RFC1123)
		return nil, fmt.Errorf("github copilot API token expired at %s", expiresAt)
	}
	modelsResponse, err := c.token.getModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get models: %v", err)
	}
	for _, model := range modelsResponse.Data {
		if model.ModelPickerEnabled && model.Policy.State == "enabled" {
			c.models[model.Name] = model.ID
			// fmt.Println(model.Name)
		}
	}
	if len(c.conf.Model) > 0 {
		if _, ok := c.models[c.conf.Model]; !ok {
			return nil, fmt.Errorf("model '%s' not found", c.conf.Model)
		}
	}
	return c, nil
}

func (c *Copilot) AvailableCopilotModels() []string {
	modelList := make([]string, 0, len(c.models))
	for model := range c.models {
		modelList = append(modelList, model)
	}
	return modelList
}

func (c *Copilot) SetModel(model string) error {
	if _, ok := c.models[model]; !ok {
		return fmt.Errorf("model '%s' not found", model)
	}
	c.conf.Model = model
	return nil
}

func readLocalToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	for _, path := range []string{
		"hosts.json",
		"apps.json",
	} {
		configPath := filepath.Join(home, ".config/github-copilot", path)
		if runtime.GOOS == "windows" {
			configPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "github-copilot", path)
		}

		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return "", err
		}

		var config map[string]json.RawMessage
		if err := json.Unmarshal(data, &config); err != nil {
			return "", fmt.Errorf("failed to parse Copilot configuration file at %s: %w", configPath, err)
		}

		for key, value := range config {
			if key == "github.com" || strings.HasPrefix(key, "github.com:") {
				var tokenData map[string]string
				if err := json.Unmarshal(value, &tokenData); err != nil {
					continue
				}
				if token, exists := tokenData["oauth_token"]; exists {
					return token, nil
				}
			}
		}
	}

	return "", fmt.Errorf("token not found in HOME/.config/github-copilot hosts.json OR apps.json")
}

func getAPIToken(ctx context.Context, oauth string) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", copilotChatAuthURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+oauth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Editor-Version", copilotEditorVersion)
	req.Header.Set("User-Agent", copilotUserAgent)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth failed: %s %s", resp.Status, body)
	}

	// data, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }
	// log.Debug(string(data))

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}

	return &tr, nil
}

func (api *tokenResponse) getModels(ctx context.Context) (*modelsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", api.Endpoints.API+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+api.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Copilot-Integration-Id", "vscode-chat")
	req.Header.Set("Editor-Version", copilotEditorVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var modelsResponse modelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&modelsResponse); err != nil {
		return nil, err
	}

	return &modelsResponse, nil
}

func (c *Copilot) Chat() (string, error) {
	reqBody := chatRequest{
		Intent:      true,
		N:           1,
		Stream:      c.conf.Stream,
		Temperature: c.conf.Temperature,
		TopP:        c.conf.TopP,
		Model:       c.models[c.conf.Model],
		Messages:    []chatMessage{{Role: "user", Content: c.conf.Prompt}},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(c.ctx, "POST", c.token.Endpoints.API+"/chat/completions", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Copilot-Integration-Id", "vscode-chat")
	req.Header.Set("Editor-Version", copilotEditorVersion)

	client := &http.Client{Timeout: 0} // no timeout for streaming
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("request failed: %s %s", resp.Status, body)
	}

	if c.conf.Stream {
		reader := bufio.NewReader(resp.Body)
		var out strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				return "", err
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			payload := strings.TrimPrefix(line, "data: ")
			if payload == "[DONE]" {
				break
			}
			var ev responseEvent
			if err := json.Unmarshal([]byte(payload), &ev); err != nil {
				return "", err
			}
			for _, choice := range ev.Choices {
				if choice.Delta != nil && choice.Delta.Content != nil {
					out.WriteString(*choice.Delta.Content)
				}
			}
		}
		return removeMarkdownCodeBlock(out.String()), nil
	} else {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		var ev responseEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			return "", err
		}
		// print full assistant message
		for _, choice := range ev.Choices {
			if choice.Message != nil {
				return removeMarkdownCodeBlock(choice.Message.Content), nil
			}
		}
	}

	return "", fmt.Errorf("no response from API")
}

/* utils */

func removeThink(content string) string {
	if strings.HasPrefix(content, "<think>") {
		if _, rest, found := strings.Cut(content, "</think>"); found {
			return rest
		}
	}
	return content
}

func removeMarkdownCodeBlock(content string) string {
	content = removeThink(content)
	if strings.HasPrefix(content, "```") {
		_, content, _ = strings.Cut(content, "\n")
	}
	return strings.TrimSuffix(content, "```")
}
