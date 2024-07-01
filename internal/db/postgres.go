package db

import (
	"fmt"

	"github.com/blacktop/ipsw/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Postgres is a database that stores data in a Postgres database.
type Postgres struct {
	URL      string
	Host     string
	Port     string
	User     string
	Password string
	Database string

	db *gorm.DB
}

// NewPostgres creates a new Postgres database.
func NewPostgres(host, port, user, password, database string) (Database, error) {
	if host == "" || port == "" || user == "" || password == "" || database == "" {
		return nil, fmt.Errorf("'host', 'port', 'user', 'password and 'database' are required")
	}
	return Postgres{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		Database: database,
	}, nil
}

// Connect connects to the database.
func (p Postgres) Connect() (err error) {
	p.db, err = gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		p.Host, p.Port, p.User, p.Database, p.Password,
	)), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect postgres database: %w", err)
	}
	return p.db.AutoMigrate(&model.IPSW{})
}

// Create creates a new entry in the database.
// It returns ErrAlreadyExists if the key already exists.
func (p Postgres) Create(i *model.IPSW) error {
	p.db.Create(i)
	return nil
}

// Get returns the value for the given key.
// It returns ErrNotFound if the key does not exist.
func (p Postgres) Get(key uint) (*model.IPSW, error) {
	i := &model.IPSW{}
	p.db.First(&i, key)
	return i, nil
}

// Set sets the value for the given key.
// It overwrites any previous value for that key.
func (p Postgres) Set(key uint, value *model.IPSW) error {
	p.db.Save(value)
	return nil
}

// Delete removes the given key.
// It returns ErrNotFound if the key does not exist.
func (p Postgres) Delete(key uint) error {
	p.db.Delete(&model.IPSW{}, key)
	return nil
}

// Close closes the database.
// It returns ErrClosed if the database is already closed.
func (p Postgres) Close() error {
	db, err := p.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
