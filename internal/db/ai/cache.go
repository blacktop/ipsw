package ai

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	model "github.com/blacktop/ipsw/internal/model/ai"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const cacheDBName = "dec.db"

// CacheDB is the interface for AI response caching.
type CacheDB interface {
	Get(uuid, provider, modelName, prompt string, temperature, topP float64) (*model.ChatResponse, error)
	Set(entry *model.ChatResponse) error
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

	if err := gormDB.AutoMigrate(&model.ChatResponse{}); err != nil {
		sqlDB, closeErr := gormDB.DB()
		if closeErr == nil {
			_ = sqlDB.Close()
		}
		return nil, fmt.Errorf("failed to auto-migrate AI cache schema: %w", err)
	}

	return &DB{db: gormDB}, nil
}

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
