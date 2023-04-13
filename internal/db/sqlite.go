package db

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/models"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// Sqlite is a database that stores data in a sqlite database.
type Sqlite struct {
	URL string

	db *gorm.DB
}

// NewSqlite creates a new Sqlite database.
func NewSqlite(path string) Database {
	return Postgres{
		URL: path,
	}
}

// Connect connects to the database.
func (s *Sqlite) Connect() (err error) {
	s.db, err = gorm.Open(sqlite.Open(s.URL), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect sqlite database: %w", err)
	}
	return s.db.AutoMigrate(&models.IPSW{})
}

// Create creates a new entry in the database.
// It returns ErrAlreadyExists if the key already exists.
func (s *Sqlite) Create(i *models.IPSW) error {
	s.db.Create(i)
	return nil
}

// Get returns the value for the given key.
// It returns ErrNotFound if the key does not exist.
func (s *Sqlite) Get(key uint) (*models.IPSW, error) {
	i := &models.IPSW{}
	s.db.First(&i, key)
	return i, nil
}

// Set sets the value for the given key.
// It overwrites any previous value for that key.
func (s *Sqlite) Set(key uint, value *models.IPSW) error {
	s.db.Save(value)
	return nil
}

// Delete removes the given key.
// It returns ErrNotFound if the key does not exist.
func (s *Sqlite) Delete(key uint) error {
	s.db.Delete(&models.IPSW{}, key)
	return nil
}

// Close closes the database.
// It returns ErrClosed if the database is already closed.
func (s *Sqlite) Close() error {
	db, err := s.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
