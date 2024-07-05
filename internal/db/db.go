// Package db provides a database interface and implementations.
package db

import (
	"github.com/blacktop/ipsw/internal/model"
)

// Database is the interface that wraps the basic database operations.
type Database interface {
	// Connect connects to the database.
	Connect() error

	// Create creates a new entry in the database.
	// It returns ErrAlreadyExists if the key already exists.
	Create(value any) error

	// Get returns the value for the given key.
	// It returns ErrNotFound if the key does not exist.
	Get(key string) (*model.Ipsw, error)

	// GetIpswByName returns the IPSW for the given name.
	// It returns ErrNotFound if the name does not exist.
	GetIpswByName(name string) (*model.Ipsw, error)

	// GetIPSW returns the IPSW for the given version, build, and device.
	// It returns ErrNotFound if the IPSW does not exist.
	GetIPSW(version, build, device string) (*model.Ipsw, error)

	// GetDSC returns the DyldSharedCache for the given UUID.
	GetDSC(uuid string) (*model.DyldSharedCache, error)

	// GetDSCImage returns the DyldSharedCache Image for the given UUID and address.
	GetDSCImage(uuid string, addr uint64) (*model.Macho, error)

	// GetMachO returns the MachO for the given UUID.
	GetMachO(uuid string) (*model.Macho, error)

	// GetSymbol returns the symbol for the given UUID and address.
	GetSymbol(uuid string, addr uint64) (*model.Symbol, error)

	// GetSymbols returns all symbols for the given UUID.
	GetSymbols(uuid string) ([]*model.Symbol, error)

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
