// Package model contains the IPSW model for the database.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrSymExists = errors.New("symbol exists")
)

// Ipsw is the model for an Ipsw file.
type Ipsw struct {
	ID         string             `gorm:"primaryKey" json:"id"`
	Name       string             `json:"name,omitempty"`
	Version    string             `json:"version,omitempty"`
	BuildID    string             `json:"buildid,omitempty"`
	Devices    []*Device          `gorm:"many2many:ipsw_devices;" json:"devices,omitempty"`
	Date       time.Time          `json:"date,omitempty"`
	Kernels    []*Kernelcache     `gorm:"many2many:ipsw_kernels;" json:"kernels,omitempty"`
	DSCs       []*DyldSharedCache `gorm:"many2many:ipsw_dscs;" json:"dscs,omitempty"`
	FileSystem []*Macho           `gorm:"many2many:ipsw_files;" json:"file_system,omitempty"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type Device struct {
	Name string `gorm:"primaryKey" json:"name"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// Kernelcache is the model for a kernelcache.
type Kernelcache struct {
	UUID      string         `gorm:"primaryKey" json:"uuid"`
	CreatedAt time.Time      `json:"created_at,omitempty"`
	UpdatedAt time.Time      `json:"updated_at,omitempty"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	Version string   `json:"version,omitempty"`
	Kexts   []*Macho `gorm:"many2many:kernelcache_kexts;" json:"kexts,omitempty"`
}

// DyldSharedCache is the model for a dyld_shared_cache.
type DyldSharedCache struct {
	UUID      string `gorm:"primaryKey" json:"uuid"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	SharedRegionStart uint64   `json:"shared_region_start,omitempty"`
	Images            []*Macho `gorm:"many2many:dsc_images;" json:"images,omitempty"`
}

type Macho struct {
	UUID      string `gorm:"primaryKey" json:"uuid"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Name      string    `json:"name,omitempty"`
	TextStart uint64    `gorm:"type:bigint" json:"text_start,omitempty"`
	TextEnd   uint64    `gorm:"type:bigint" json:"text_end,omitempty"`
	Symbols   []*Symbol `gorm:"many2many:macho_syms;"`
}

// swagger:model
type Symbol struct {
	// swagger:ignore
	gorm.Model
	Symbol string `json:"symbol"`
	Start  uint64 `gorm:"type:bigint" json:"start"`
	End    uint64 `gorm:"type:bigint" json:"end"`
}

func (s Symbol) String() string {
	return fmt.Sprintf("%#x: %s", s.Start, s.Symbol)
}

func (s Symbol) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Symbol string `json:"symbol"`
		Start  uint64 `json:"start"`
		End    uint64 `json:"end"`
	}{
		Symbol: s.Symbol,
		Start:  s.Start,
		End:    s.End,
	})
}
