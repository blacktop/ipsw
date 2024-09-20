package db

import (
	"encoding/gob"
	"fmt"
	"os"
	"slices"

	"github.com/blacktop/ipsw/internal/model"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

// Memory is a database that stores data in memory.
type Memory struct {
	IPSWs map[string]*model.Ipsw
	Path  string
}

// NewInMemory creates a new in-memory database.
func NewInMemory(path string) (Database, error) {
	if path == "" {
		return nil, errors.New("'path' is required")
	}
	return &Memory{
		IPSWs: make(map[string]*model.Ipsw),
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
func (m *Memory) Create(value any) error {
	if ipsw, ok := value.(*model.Ipsw); ok {
		if _, exists := m.IPSWs[ipsw.ID]; exists {
			return gorm.ErrDuplicatedKey
		}
		m.IPSWs[ipsw.ID] = ipsw
		return nil
	}
	return fmt.Errorf("invalid type: %T", value)
}

// Get returns the IPSW for the given key.
// It returns ErrNotFound if the key does not exist.
func (m *Memory) Get(id string) (*model.Ipsw, error) {
	ipsw, exists := m.IPSWs[id]
	if !exists {
		return nil, errors.Errorf("no IPSW found with id: %s", id)
	}
	return ipsw, nil
}

// GetIpswByName returns the IPSW for the given name.
// It returns ErrNotFound if the key does not exist.
func (m *Memory) GetIpswByName(name string) (*model.Ipsw, error) {
	for _, ipsw := range m.IPSWs {
		if ipsw.Name == name {
			return ipsw, nil
		}
	}
	return nil, model.ErrNotFound
}

// GetIPSW returns the IPSW for the given version, build, and device.
// It returns ErrNotFound if the IPSW does not exist.
func (m *Memory) GetIPSW(version, build, device string) (*model.Ipsw, error) {
	for _, ipsw := range m.IPSWs {
		if ipsw.Version == version && ipsw.BuildID == build {
			var devs []string
			for _, dev := range ipsw.Devices {
				devs = append(devs, dev.Name)
			}
			if slices.Contains(devs, device) {
				return ipsw, nil
			}
		}
	}
	return nil, model.ErrNotFound
}

func (m *Memory) GetDSC(uuid string) (*model.DyldSharedCache, error) {
	for _, ipsw := range m.IPSWs {
		for _, dyld := range ipsw.DSCs {
			if dyld.UUID == uuid {
				return dyld, nil
			}
		}
	}
	return nil, model.ErrNotFound
}

func (m *Memory) GetDSCImage(uuid string, addr uint64) (*model.Macho, error) {
	for _, ipsw := range m.IPSWs {
		for _, dyld := range ipsw.DSCs {
			if dyld.UUID == uuid {
				for _, img := range dyld.Images {
					if addr >= img.TextStart && addr < img.TextEnd {
						return img, nil
					}
				}
			}
		}
	}
	return nil, model.ErrNotFound
}

func (m *Memory) GetMachO(uuid string) (*model.Macho, error) {
	for _, ipsw := range m.IPSWs {
		for _, dyld := range ipsw.DSCs {
			for _, img := range dyld.Images {
				if img.UUID == uuid {
					return img, nil
				}
			}
		}
		for _, fs := range ipsw.FileSystem {
			if fs.UUID == uuid {
				return fs, nil
			}
		}
		for _, fs := range ipsw.Kernels {
			for _, kext := range fs.Kexts {
				if kext.UUID == uuid {
					return kext, nil
				}
			}
		}
	}
	return nil, model.ErrNotFound
}

func (m *Memory) GetSymbol(uuid string, addr uint64) (*model.Symbol, error) {
	for _, ipsw := range m.IPSWs {
		for _, dyld := range ipsw.DSCs {
			for _, img := range dyld.Images {
				if img.UUID == uuid {
					for _, sym := range img.Symbols {
						if addr >= sym.Start && addr < sym.End {
							return sym, nil
						}
					}
				}
			}
		}
		for _, fs := range ipsw.FileSystem {
			if fs.UUID == uuid {
				for _, sym := range fs.Symbols {
					if addr >= sym.Start && addr < sym.End {
						return sym, nil
					}
				}
			}
		}
		for _, fs := range ipsw.Kernels {
			for _, kext := range fs.Kexts {
				if fs.UUID == uuid {
					for _, sym := range kext.Symbols {
						if addr >= sym.Start && addr < sym.End {
							return sym, nil
						}
					}
				}
			}
		}
	}
	return nil, model.ErrNotFound
}

func (m *Memory) GetSymbols(uuid string) ([]*model.Symbol, error) {
	for _, ipsw := range m.IPSWs {
		for _, dyld := range ipsw.DSCs {
			for _, img := range dyld.Images {
				if img.UUID == uuid {
					return img.Symbols, nil
				}
			}
		}
		for _, fs := range ipsw.FileSystem {
			if fs.UUID == uuid {
				return fs.Symbols, nil
			}
		}
		for _, fs := range ipsw.Kernels {
			for _, kext := range fs.Kexts {
				if fs.UUID == uuid {
					return kext.Symbols, nil
				}
			}
		}
	}
	return nil, model.ErrNotFound
}

// Set sets the value for the given key.
// It overwrites any previous value for that key.
func (m *Memory) Save(value any) error {
	if ipsw, ok := value.(*model.Ipsw); ok {
		m.IPSWs[ipsw.ID] = ipsw
	}
	return nil
}

func (m *Memory) List(version string) ([]*model.Ipsw, error) {
	ipsws := []*model.Ipsw{}
	for _, p := range m.IPSWs {
		if p.Version == version {
			ipsws = append(ipsws, p)
		}
	}
	return ipsws, nil
}

// Delete removes the given key.
// It returns ErrNotFound if the key does not exist.
func (m *Memory) Delete(id string) error {
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
	gob.Register([]any{})
	gob.Register(map[string]any{})
	return gob.NewEncoder(f).Encode(m.IPSWs)
}
