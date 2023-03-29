// Package db provides a database interface and implementations.
package db

import "github.com/blacktop/ipsw/internal/models"

// Database is the interface that wraps the basic database operations.
type Database interface {
	// Connect connects to the database.
	Connect() error

	// Create creates a new entry in the database.
	// It returns ErrAlreadyExists if the key already exists.
	Create(i *models.IPSW) error

	// Get returns the value for the given key.
	// It returns ErrNotFound if the key does not exist.
	Get(key uint) (*models.IPSW, error)

	// Set sets the value for the given key.
	// It overwrites any previous value for that key.
	Set(key uint, value *models.IPSW) error

	// Delete removes the given key.
	// It returns ErrNotFound if the key does not exist.
	Delete(key uint) error

	// Close closes the database.
	// It returns ErrClosed if the database is already closed.
	Close() error
}
