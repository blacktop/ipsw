package ai

import (
	"errors"

	"gorm.io/gorm"
)

var ErrNotFound = errors.New("not found")

// ChatResponse represents a cached AI response in the database.
type ChatResponse struct {
	gorm.Model
	UUID        string  `gorm:"index"`
	Provider    string  `gorm:"index"`
	LLMModel    string  `gorm:"index"`
	Prompt      string  `gorm:"index"`
	Temperature float64 `gorm:"index"`
	TopP        float64 `gorm:"index"`
	// Stream bool // Decided to not cache streaming responses for now, or cache only the full aggregated response.
	Response string
}

// CopilotToken represents a cached Copilot API token.
type CopilotToken struct {
	gorm.Model
	Key               string `gorm:"uniqueIndex"` // A unique key to identify this token, e.g., "active_copilot_token"
	Token             string // The API token (tokenResponse.Token)
	ExpiresAt         int64  // Unix timestamp (tokenResponse.ExpiresAt)
	TokenResponseJSON string // JSON marshaled full tokenResponse
}

// ProviderModels represents cached AI provider models in the database.
type ProviderModels struct {
	gorm.Model
	Provider   string `gorm:"uniqueIndex"` // e.g., "copilot", "openai"
	ModelsJSON string // JSON marshaled map[string]string of model name to model ID
}
