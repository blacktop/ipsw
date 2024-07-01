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

// IPSW is the model for an IPSW file.
type IPSW struct {
	gorm.Model                   // adds ID, created_at etc.
	Name       string            `json:"name,omitempty"`
	Version    string            `json:"version,omitempty"`
	BuildID    string            `json:"buildid,omitempty"`
	Devices    []Device          `gorm:"many2many:ipsw_devices;" json:"devices,omitempty"`
	Date       time.Time         `json:"date,omitempty"`
	Kernels    []Kernelcache     `gorm:"many2many:ipsw_kernels;" json:"kernels,omitempty"`
	DSCs       []DyldSharedCache `gorm:"many2many:ipsw_dscs;" json:"dscs,omitempty"`
	FileSystem FileSystem        `json:"files"`
}

type Device struct {
	gorm.Model
	Name string `json:"name"`
}

// Kernelcache is the model for a kernelcache.
type Kernelcache struct {
	UUID      string `gorm:"primaryKey" json:"uuid"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Version string  `json:"version"`
	Kexts   []MachO `gorm:"many2many:kernelcache_kexts;" json:"kexts,omitempty"`
}

// DyldSharedCache is the model for a dyld_shared_cache.
type DyldSharedCache struct {
	UUID      string `gorm:"primaryKey" json:"uuid"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Version string  `json:"version,omitempty"`
	Header  string  `json:"header,omitempty"`
	Images  []MachO `gorm:"many2many:dsc_images;" json:"images,omitempty"`
}

type FileSystem struct {
	gorm.Model
	AppOS    []MachO `gorm:"many2many:appos_files;" json:"app_os,omitempty"`
	SystemOS []MachO `gorm:"many2many:systemos_files;" json:"system_os,omitempty"`
	FS       []MachO `gorm:"many2many:fs_files;" json:"fs,omitempty"`
	IPSWID   uint
}

type MachO struct {
	UUID      string `gorm:"primaryKey" json:"uuid"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`

	Name    string   `json:"name,omitempty"`
	Symbols []Symbol `gorm:"many2many:macho_syms;"`
}

type Symbol struct {
	gorm.Model
	Symbol *string `json:"symbol"`
	Start  uint64  `json:"start"`
	End    uint64  `json:"end"`
}
