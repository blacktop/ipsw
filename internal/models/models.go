// Package models contains the models for the database.
package models

import (
	"os"
	"time"

	"gorm.io/gorm"
)

// IPSW is the model for an IPSW file.
type IPSW struct {
	gorm.Model                   // adds ID, created_at etc.
	Version    string            `json:"version"`
	BuildID    string            `json:"buildid"`
	Devices    []string          `json:"devices"`
	Date       time.Time         `json:"date"`
	Kernels    []Kernelcache     `json:"kernels"`
	DSCs       []DyldSharedCache `json:"dscs"`
	Files      FileSystem        `json:"files"`
}

// Kernelcache is the model for a kernelcache.
type Kernelcache struct {
	gorm.Model
	Version string `json:"version"`
}

// DyldSharedCache is the model for a dyld_shared_cache.
type DyldSharedCache struct {
	gorm.Model
	Version string `json:"version"`
	Header  string `json:"header"`
}

type FileSystem struct {
	gorm.Model
	Files []File `json:"files"`
}

type File struct {
	gorm.Model
	Name string      `json:"name"`
	Info os.FileInfo `json:"info"`
}
