// Package model contains the IPSW model for the database.
package model

import (
	"errors"
	"fmt"
	"time"

	"github.com/blacktop/go-macho/types"
	"github.com/uptrace/bun"
)

var (
	ErrAlreadyExists           = errors.New("already exists")
	ErrInvalidTransactionState = errors.New("invalid transaction state")
	ErrNotFound                = errors.New("not found")
	ErrSymExists               = errors.New("symbol exists")
)

// Ipsw is the model for an Ipsw file.
type Ipsw struct {
	bun.BaseModel `bun:"table:ipsws,alias:i"`

	ID         int64             `bun:",pk,autoincrement"`
	SHA256     string            `bun:",unique" json:"sha256,omitempty"`
	Name       string            `json:"name,omitempty"`
	Version    string            `json:"version,omitempty"`
	BuildID    string            `json:"buildid,omitempty"`
	Devices    []Device          `bun:"m2m:ipsw_to_devices,join:Ipsw=Device"`
	Kernels    []Kernelcache     `bun:"m2m:ipsw_to_kernelcaches,join:Ipsw=Kernelcache"`
	DSCs       []DyldSharedCache `bun:"m2m:ipsw_to_dyldsharedcaches,join:Ipsw=DyldSharedCache"`
	FileSystem []Macho           `bun:"m2m:ipsw_to_machos,join:Ipsw=Macho"`

	CreatedAt time.Time    `bun:",nullzero,notnull,default:current_timestamp"`
	UpdatedAt time.Time    `bun:",nullzero,notnull,default:current_timestamp"`
	DeletedAt bun.NullTime `bun:",soft_delete,nullzero"`
}

type IpswToDevice struct {
	bun.BaseModel `bun:"table:ipsw_to_devices,alias:i2d"`
	IpswID        int64   `bun:",pk"`
	Ipsw          *Ipsw   `bun:"rel:belongs-to,join:ipsw_id=id"`
	DeviceID      int64   `bun:",pk"`
	Device        *Device `bun:"rel:belongs-to,join:device_id=id"`
}

type IpswToKernelcache struct {
	bun.BaseModel `bun:"table:ipsw_to_kernelcaches,alias:i2k"`
	IpswID        int64        `bun:",pk"`
	Ipsw          *Ipsw        `bun:"rel:belongs-to,join:ipsw_id=id"`
	KernelcacheID int64        `bun:",pk"`
	Kernelcache   *Kernelcache `bun:"rel:belongs-to,join:kernelcache_id=id"`
}

type IpswToDyldSharedCache struct {
	bun.BaseModel     `bun:"table:ipsw_to_dyldsharedcaches,alias:i2dsc"`
	IpswID            int64            `bun:",pk"`
	Ipsw              *Ipsw            `bun:"rel:belongs-to,join:ipsw_id=id"`
	DyldSharedCacheID int64            `bun:",pk"`
	DyldSharedCache   *DyldSharedCache `bun:"rel:belongs-to,join:dyld_shared_cache_id=id"`
}

type IpswToMacho struct {
	bun.BaseModel `bun:"table:ipsw_to_machos,alias:i2m"`
	IpswID        int64  `bun:",pk"`
	Ipsw          *Ipsw  `bun:"rel:belongs-to,join:ipsw_id=id"`
	MachoID       int64  `bun:",pk"`
	Macho         *Macho `bun:"rel:belongs-to,join:macho_id=id"`
}

type Device struct {
	bun.BaseModel `bun:"table:devices,alias:d"`

	ID   int64  `bun:",pk,autoincrement"`
	Name string `bun:",unique" json:"name"`
}

// Kernelcache is the model for a kernelcache.
type Kernelcache struct {
	bun.BaseModel `bun:"table:kernelcaches,alias:k"`

	ID        int64        `bun:",pk,autoincrement"`
	UUID      types.UUID   `bun:"type:uuid,unique" json:"uuid"`
	CreatedAt time.Time    `bun:",nullzero,notnull,default:current_timestamp"`
	UpdatedAt time.Time    `bun:",nullzero,notnull,default:current_timestamp"`
	DeletedAt bun.NullTime `bun:",soft_delete,nullzero"`

	Version string  `json:"version,omitempty"`
	Kexts   []Macho `bun:"m2m:kernelcache_to_machos,join:Kernelcache=Macho"`
}

type KernelcacheToMacho struct {
	bun.BaseModel `bun:"table:kernelcache_to_machos,alias:k2m"`
	KernelcacheID int64        `bun:",pk"`
	Kernelcache   *Kernelcache `bun:"rel:belongs-to,join:kernelcache_id=id"`
	MachoID       int64        `bun:",pk"`
	Macho         *Macho       `bun:"rel:belongs-to,join:macho_id=id"`
}

// DyldSharedCache is the model for a dyld_shared_cache.
type DyldSharedCache struct {
	bun.BaseModel `bun:"table:dyld_shared_caches,alias:dsc"`

	ID        int64        `bun:",pk,autoincrement"`
	UUID      types.UUID   `bun:"type:uuid,unique" json:"uuid"`
	CreatedAt time.Time    `bun:",nullzero,notnull,default:current_timestamp"`
	UpdatedAt time.Time    `bun:",nullzero,notnull,default:current_timestamp"`
	DeletedAt bun.NullTime `bun:",soft_delete,nullzero"`

	SharedRegionStart uint64  `json:"shared_region_start,omitempty"`
	Images            []Macho `bun:"m2m:dsc_to_machos,join:DyldSharedCache=Macho"`
}

type DyldSharedCacheToMacho struct {
	bun.BaseModel     `bun:"table:dsc_to_machos,alias:d2m"`
	DyldSharedCacheID int64            `bun:",pk"`
	DyldSharedCache   *DyldSharedCache `bun:"rel:belongs-to,join:dyld_shared_cache_id=id"`
	MachoID           int64            `bun:",pk"`
	Macho             *Macho           `bun:"rel:belongs-to,join:macho_id=id"`
}

type Path struct {
	bun.BaseModel `bun:"table:paths,alias:p"`

	ID   int64  `bun:",pk,autoincrement"`
	Path string `bun:",unique" json:"path,omitempty"`
}

type Macho struct {
	bun.BaseModel `bun:"table:machos,alias:m"`

	ID        int64      `bun:",pk,autoincrement"`
	UUID      types.UUID `bun:"type:uuid,unique" json:"uuid"`
	PathID    int64
	Path      Path     `bun:"rel:belongs-to,join:path_id=id"`
	TextStart uint64   `bun:"type:bigint" json:"text_start,omitempty"`
	TextEnd   uint64   `bun:"type:bigint" json:"text_end,omitempty"`
	Symbols   []Symbol `bun:"m2m:macho_to_symbols,join:Macho=Symbol"`
}

func (m Macho) GetPath() string {
	return m.Path.Path
}

type MachoToSymbol struct {
	bun.BaseModel `bun:"table:macho_to_symbols,alias:m2s"`
	MachoID       int64   `bun:",pk"`
	Macho         *Macho  `bun:"rel:belongs-to,join:macho_id=id"`
	SymbolID      int64   `bun:",pk"`
	Symbol        *Symbol `bun:"rel:belongs-to,join:symbol_id=id"`
}

type Name struct {
	bun.BaseModel `bun:"table:names,alias:n"`

	ID   int64  `bun:",pk,autoincrement"`
	Name string `bun:",unique" json:"name,omitempty"`
}

// swagger:model
type Symbol struct {
	bun.BaseModel `bun:"table:symbols,alias:s"`

	ID     int64 `bun:",pk,autoincrement"`
	NameID int64
	Name   Name   `bun:"rel:belongs-to,join:name_id=id"`
	Start  uint64 `bun:"type:bigint" json:"start"`
	End    uint64 `bun:"type:bigint" json:"end"`
}

func (s Symbol) GetName() string {
	return s.Name.Name
}

func (s Symbol) String() string {
	return fmt.Sprintf("%#x: %s", s.Start, s.Name.Name)
}
