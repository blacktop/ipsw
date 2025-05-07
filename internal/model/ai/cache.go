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
