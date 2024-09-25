// Package model contains the IPSW model for the database.
package model

import (
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
	Kernels    []*Kernelcache     `gorm:"many2many:ipsw_kernels;" json:"kernels,omitempty"`
	DSCs       []*DyldSharedCache `gorm:"many2many:ipsw_dscs;" json:"dscs,omitempty"`
	FileSystem []*Macho           `gorm:"many2many:ipsw_files;" json:"file_system,omitempty"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type Device struct {
	Name string `gorm:"primaryKey" json:"name"`
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

type Path struct {
	// swagger:ignore
	ID   uint   `gorm:"primaryKey"`
	Path string `gorm:"uniqueIndex" json:"name,omitempty"`
}

type Macho struct {
	UUID string `gorm:"primaryKey" json:"uuid"`
	// swagger:ignore
	PathID    uint
	Path      Path      `gorm:"foreignKey:PathID"`
	TextStart uint64    `gorm:"type:bigint" json:"text_start,omitempty"`
	TextEnd   uint64    `gorm:"type:bigint" json:"text_end,omitempty"`
	Symbols   []*Symbol `gorm:"many2many:macho_syms;"`
}

func (m Macho) GetPath() string {
	return m.Path.Path
}

type Name struct {
	// swagger:ignore
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"uniqueIndex" json:"name,omitempty"`
}

// swagger:model
type Symbol struct {
	// swagger:ignore
	ID uint `gorm:"primaryKey"`
	// swagger:ignore
	NameID uint
	Name   Name   `gorm:"foreignKey:NameID"`
	Start  uint64 `gorm:"type:bigint" json:"start"`
	End    uint64 `gorm:"type:bigint" json:"end"`
}

func (s Symbol) GetName() string {
	return s.Name.Name
}

func (s Symbol) String() string {
	return fmt.Sprintf("%#x: %s", s.Start, s.Name.Name)
}
