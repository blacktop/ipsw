// Package model contains the IPSW model for the database.
package model

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

var (
	ErrNotFound  = errors.New("no ipsw found")
	ErrSymExists = errors.New("symbol exists")
)

// Ipsw is the model for an Ipsw file.
type Ipsw struct {
	gorm.Model                    // adds ID, created_at etc.
	ID         string             `gorm:"primaryKey" json:"id"`
	Name       string             `json:"name,omitempty"`
	Version    string             `json:"version,omitempty"`
	BuildID    string             `json:"buildid,omitempty"`
	Devices    []*Device          `gorm:"many2many:ipsw_devices;" json:"devices,omitempty"`
	Date       time.Time          `json:"date,omitempty"`
	Kernels    []*Kernelcache     `gorm:"many2many:ipsw_kernels;" json:"kernels,omitempty"`
	DSCs       []*DyldSharedCache `gorm:"many2many:ipsw_dscs;" json:"dscs,omitempty"`
	FileSystem []*Macho           `gorm:"many2many:ipsw_files;" json:"file_system,omitempty"`
}

type Device struct {
	Name      string `gorm:"primaryKey" json:"name"`
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

	Version string   `json:"version,omitempty"`
	Header  string   `json:"header,omitempty"`
	Images  []*Macho `gorm:"many2many:dsc_images;" json:"images,omitempty"`
}

type Macho struct {
	UUID      string `gorm:"primaryKey" json:"uuid"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Name    string    `json:"name,omitempty"`
	Symbols []*Symbol `gorm:"many2many:macho_syms;"`
}

type Symbol struct {
	gorm.Model
	Symbol string `json:"symbol"`
	Start  string `json:"start"`
	End    string `json:"end"`
}
