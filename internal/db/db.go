// Package db provides a database interface and implementations.
package db

import (
	"github.com/blacktop/ipsw/internal/model"
	"gorm.io/gorm"
)

// Database is the interface that wraps the basic database operations.
type Database interface {
	// Connect connects to the database.
	Connect() error

	// Create creates a new entry in the database.
	// It returns ErrAlreadyExists if the key already exists.
	Create(value any) error

	DB() *gorm.DB

	// Get returns the value for the given key.
	// It returns ErrNotFound if the key does not exist.
	Get(key string) (*model.Ipsw, error)

	// Get returns the value for the given key.
	// It returns ErrNotFound if the key does not exist.
	GetByName(name string) (*model.Ipsw, error)

	// Save updates the IPSW.
	// It overwrites any previous value for that IPSW.
	Save(value any) error

	// Delete removes the given key.
	// It returns ErrNotFound if the key does not exist.
	Delete(key string) error

	// Close closes the database.
	// It returns ErrClosed if the database is already closed.
	Close() error
}
