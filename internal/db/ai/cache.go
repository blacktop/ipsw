package ai

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	model "github.com/blacktop/ipsw/internal/model/ai"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const cacheDBName = "dec.db"

// CacheDB is the interface for AI response caching.
type CacheDB interface {
	Get(uuid, provider, modelName, prompt string, temperature, topP float64) (*model.ChatResponse, error)
	Set(entry *model.ChatResponse) error
	// Copilot Token Caching
	GetToken(key string) (*model.CopilotToken, error)
	SetToken(token *model.CopilotToken) error
	// Provider Models Caching
	GetProviderModels(providerName string) (*model.ProviderModels, error)
	SetProviderModels(models *model.ProviderModels) error
	DeleteProviderModels(providerName string) error
	Close() error
}

type DB struct {
	db *gorm.DB
}

// NewCacheDB creates a new CacheDB instance using SQLite.
func NewCacheDB(verbose bool) (CacheDB, error) {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user config directory: %w", err)
	}

	ipswConfigDir := filepath.Join(userConfigDir, "ipsw")
	if err := os.MkdirAll(ipswConfigDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create ipsw config directory '%s': %w", ipswConfigDir, err)
	}

	dbPath := filepath.Join(ipswConfigDir, cacheDBName)

	gormDB, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		SkipDefaultTransaction: true,
		TranslateError:         true,
		Logger:                 logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to AI cache sqlite database at '%s': %w", dbPath, err)
	}
	if verbose {
		gormDB.Logger = logger.Default.LogMode(logger.Info)
	}

	if err := gormDB.AutoMigrate(
		&model.ChatResponse{},
		&model.CopilotToken{},
		&model.ProviderModels{},
	); err != nil {
		sqlDB, closeErr := gormDB.DB()
		if closeErr == nil {
			_ = sqlDB.Close()
		}
		return nil, fmt.Errorf("failed to auto-migrate AI cache schema: %w", err)
	}

	return &DB{db: gormDB}, nil
}

/*
	Chat Response Caching Methods
*/

// Get fetches an entry from the AI cache by parameters.
func (d *DB) Get(uuid, provider, modelName, prompt string, temperature, topP float64) (*model.ChatResponse, error) {
	var entry model.ChatResponse
	// Query by all relevant parameters using the composite index
	if err := d.db.Where(&model.ChatResponse{
		UUID:        uuid,
		Provider:    provider,
		LLMModel:    modelName,
		Prompt:      prompt,
		Temperature: temperature,
		TopP:        topP,
	}).First(&entry).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, gorm.ErrRecordNotFound // Return gorm's error directly for cache miss
		}
		return nil, fmt.Errorf("failed to get AI cache entry: %w", err)
	}
	return &entry, nil
}

// Set stores an entry in the AI cache.
func (d *DB) Set(entry *model.ChatResponse) error {
	if err := d.db.Create(entry).Error; err != nil {
		return fmt.Errorf("failed to set AI cache entry: %w", err)
	}
	return nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying DB instance: %w", err)
	}
	return sqlDB.Close()
}

/*
	Copilot Token Caching Methods
*/

// GetToken retrieves a cached Copilot token.
func (d *DB) GetToken(key string) (*model.CopilotToken, error) {
	var token model.CopilotToken
	if err := d.db.Where("key = ?", key).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound // Use your defined ErrNotFound from model pkg
		}
		return nil, fmt.Errorf("failed to get copilot token from cache: %w", err)
	}
	return &token, nil
}

// SetToken stores or updates a Copilot token in the cache.
func (d *DB) SetToken(tokenToSet *model.CopilotToken) error {
	// Attempt to find by key, then update or create.
	// Using Assign to either update the existing record or create a new one if not found.
	if err := d.db.Where(model.CopilotToken{Key: tokenToSet.Key}).Assign(tokenToSet).FirstOrCreate(tokenToSet).Error; err != nil {
		return fmt.Errorf("failed to set copilot token in cache: %w", err)
	}
	return nil
}

/*
	Provider Models Caching Methods
*/

// GetProviderModels retrieves cached models for a provider.
func (d *DB) GetProviderModels(provider string) (*model.ProviderModels, error) {
	var pm model.ProviderModels
	if err := d.db.Where("provider = ?", provider).First(&pm).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get provider models from cache for %s: %w", provider, err)
	}
	return &pm, nil
}

// SetProviderModels stores or updates cached models for a provider.
func (d *DB) SetProviderModels(modelsToSet *model.ProviderModels) error {
	// This will update the ModelsJSON if the provider already exists, or insert if it doesn't
	if err := d.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "provider"}},
		DoUpdates: clause.AssignmentColumns([]string{"models_json", "updated_at"}),
	}).Create(modelsToSet).Error; err != nil {
		return fmt.Errorf("failed to upsert provider models in cache for %s: %w", modelsToSet.Provider, err)
	}
	return nil
}

// DeleteProviderModels removes cached models for a provider.
func (d *DB) DeleteProviderModels(provider string) error {
	if err := d.db.Where("provider = ?", provider).Delete(&model.ProviderModels{}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // Not an error if it's already gone or never existed
		}
		return fmt.Errorf("failed to delete provider models from cache for %s: %w", provider, err)
	}
	return nil
}
