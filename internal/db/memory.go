package db

import (
	"encoding/gob"
	"os"

	"github.com/blacktop/ipsw/internal/model"
	"github.com/pkg/errors"
)

// Memory is a database that stores data in memory.
type Memory struct {
	IPSWs map[uint]*model.IPSW
	Path  string
}

// NewInMemory creates a new in-memory database.
func NewInMemory(path string) (Database, error) {
	if path == "" {
		return nil, errors.New("'path' is required")
	}
	return &Memory{
		IPSWs: make(map[uint]*model.IPSW),
		Path:  path,
	}, nil
}

// Connect connects to the database.
func (m *Memory) Connect() error {
	f, err := os.Open(m.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewDecoder(f).Decode(&m.IPSWs)
}

// Create creates a new entry in the database.
// It returns ErrAlreadyExists if the key already exists.
func (m *Memory) Create(i *model.IPSW) error {
	m.IPSWs[i.ID] = i
	return nil
}

// Get returns the value for the given key.
// It returns ErrNotFound if the key does not exist.
func (m *Memory) Get(id uint) (*model.IPSW, error) {
	pet, exists := m.IPSWs[id]
	if !exists {
		return nil, errors.Errorf("no IPSW found with id: %d", id)
	}
	return pet, nil
}

// Set sets the value for the given key.
// It overwrites any previous value for that key.
func (m *Memory) Set(key uint, value *model.IPSW) error {
	m.IPSWs[key] = value
	return nil
}

func (m *Memory) List(version string) ([]*model.IPSW, error) {
	ipsws := []*model.IPSW{}
	for _, p := range m.IPSWs {
		if p.Version == version {
			ipsws = append(ipsws, p)
		}
	}
	return ipsws, nil
}

// Delete removes the given key.
// It returns ErrNotFound if the key does not exist.
func (m *Memory) Delete(id uint) error {
	delete(m.IPSWs, id)
	return nil
}

// Close closes the database.
// It returns ErrClosed if the database is already closed.
func (m *Memory) Close() error {
	f, err := os.Open(m.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	return gob.NewEncoder(f).Encode(m.IPSWs)
}
