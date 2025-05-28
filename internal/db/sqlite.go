package db

import (
	"errors"
	"fmt"

	"github.com/blacktop/ipsw/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Sqlite is a database that stores data in a sqlite database.
type Sqlite struct {
	URL string
	// Config
	BatchSize int

	db *gorm.DB
}

// NewSqlite creates a new Sqlite database.
func NewSqlite(path string, batchSize int) (Database, error) {
	if path == "" {
		return nil, fmt.Errorf("'path' is required")
	}
	return &Sqlite{
		URL:       path,
		BatchSize: batchSize,
	}, nil
}

// Connect connects to the database.
func (s *Sqlite) Connect() (err error) {
	s.db, err = gorm.Open(sqlite.Open(s.URL), &gorm.Config{
		CreateBatchSize:        s.BatchSize,
		SkipDefaultTransaction: true,
		TranslateError:         true,
		Logger:                 logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect sqlite database: %w", err)
	}
	return s.db.AutoMigrate(
		&model.Ipsw{},
		&model.Device{},
		&model.Kernelcache{},
		&model.DyldSharedCache{},
		&model.Macho{},
		&model.Symbol{},
		&model.Entitlement{},
		&model.EntitlementKey{},
	)
}

// Create creates a new entry in the database.
// It returns ErrAlreadyExists if the key already exists.
func (s *Sqlite) Create(value any) error {
	// if result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(value); result.Error != nil {
	if result := s.db.Create(value); result.Error != nil {
		return result.Error
	}
	return nil
}

// Get returns the value for the given key.
// It returns ErrNotFound if the key does not exist.
func (s *Sqlite) Get(key string) (*model.Ipsw, error) {
	i := &model.Ipsw{}
	s.db.First(&i, key)
	return i, nil
}

// GetIpswByName returns the IPSW for the given name.
// It returns ErrNotFound if the key does not exist.
func (s *Sqlite) GetIpswByName(name string) (*model.Ipsw, error) {
	i := &model.Ipsw{Name: name}
	if result := s.db.First(&i); result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, result.Error
	}
	return i, nil
}

func (s *Sqlite) GetIPSW(version, build, device string) (*model.Ipsw, error) {
	var ipsw model.Ipsw
	if err := s.db.Joins("JOIN ipsw_devices ON ipsw_devices.ipsw_id = ipsws.id").
		Joins("JOIN devices ON devices.name = ipsw_devices.device_name").
		Where("ipsws.version = ? AND ipsws.build_id = ? AND devices.name = ?", version, build, device).
		First(&ipsw).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &ipsw, nil
}

func (s *Sqlite) GetDSC(uuid string) (*model.DyldSharedCache, error) {
	var dsc model.DyldSharedCache
	if err := s.db.Where("uuid = ?", uuid).First(&dsc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &dsc, nil
}

func (s *Sqlite) GetDSCImage(uuid string, address uint64) (*model.Macho, error) {
	var macho model.Macho
	if err := s.db.Joins("JOIN dsc_images ON dsc_images.macho_uuid = machos.uuid").
		Joins("JOIN dyld_shared_caches ON dyld_shared_caches.uuid = dsc_images.dyld_shared_cache_uuid").
		Where("dyld_shared_caches.uuid = ? AND machos.text_start <= ? AND ? < machos.text_end", uuid, address, address).
		First(&macho).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &macho, nil
}

func (s *Sqlite) GetMachO(uuid string) (*model.Macho, error) {
	var macho model.Macho
	if err := s.db.Where("uuid = ?", uuid).First(&macho).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &macho, nil
}

func (s *Sqlite) GetSymbol(uuid string, address uint64) (*model.Symbol, error) {
	var symbol model.Symbol
	if err := s.db.Joins("JOIN macho_syms ON macho_syms.symbol_id = symbols.id").
		Joins("JOIN machos ON machos.uuid = macho_syms.macho_uuid").
		Where("machos.uuid = ? AND symbols.start <= ? AND ? < symbols.end", uuid, address, address).
		First(&symbol).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &symbol, nil
}

func (s *Sqlite) GetSymbols(uuid string) ([]*model.Symbol, error) {
	var syms []*model.Symbol
	if err := s.db.Joins("JOIN macho_syms ON macho_syms.symbol_id = symbols.id").
		Joins("JOIN machos ON machos.uuid = macho_syms.macho_uuid").
		Where("machos.uuid = ?", uuid).
		Find(syms).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return syms, nil
}

// CreateEntitlement creates a new entitlement entry in the database
func (s *Sqlite) CreateEntitlement(entitlement *model.Entitlement) error {
	if result := s.db.Create(entitlement); result.Error != nil {
		return result.Error
	}
	return nil
}

// GetEntitlementsByIPSW returns all entitlements for a given IPSW
func (s *Sqlite) GetEntitlementsByIPSW(ipswID string) ([]*model.Entitlement, error) {
	var entitlements []*model.Entitlement
	if err := s.db.Preload("Keys").Where("ipsw_id = ?", ipswID).Find(&entitlements).Error; err != nil {
		return nil, err
	}
	return entitlements, nil
}

// SearchEntitlements searches for entitlements based on query parameters
func (s *Sqlite) SearchEntitlements(query *model.EntitlementQuery) ([]*model.Entitlement, error) {
	var entitlements []*model.Entitlement

	dbQuery := s.db.Preload("Keys").Preload("Ipsw").Preload("Ipsw.Devices")

	// Join with IPSW table for version/build filtering
	if query.Version != "" || query.Build != "" {
		dbQuery = dbQuery.Joins("JOIN ipsws ON ipsws.id = entitlements.ipsw_id")
		if query.Version != "" {
			dbQuery = dbQuery.Where("ipsws.version = ?", query.Version)
		}
		if query.Build != "" {
			dbQuery = dbQuery.Where("ipsws.build_id = ?", query.Build)
		}
	}

	// Filter by device
	if query.Device != "" {
		dbQuery = dbQuery.Joins("JOIN ipsw_devices ON ipsw_devices.ipsw_id = entitlements.ipsw_id").
			Where("ipsw_devices.device_name = ?", query.Device)
	}

	// Filter by file path
	if query.FilePath != "" {
		dbQuery = dbQuery.Where("entitlements.file_path LIKE ?", "%"+query.FilePath+"%")
	}

	// Filter by entitlement key
	if query.KeyPattern != "" {
		dbQuery = dbQuery.Joins("JOIN entitlement_keys ON entitlement_keys.entitlement_id = entitlements.id").
			Where("entitlement_keys.key REGEXP ?", query.KeyPattern)
	}

	// Filter by entitlement value
	if query.ValuePattern != "" {
		dbQuery = dbQuery.Joins("LEFT JOIN entitlement_keys ek ON ek.entitlement_id = entitlements.id").
			Where("ek.string_value REGEXP ? OR ek.array_value REGEXP ? OR ek.dict_value REGEXP ?",
				query.ValuePattern, query.ValuePattern, query.ValuePattern)
	}

	if err := dbQuery.Find(&entitlements).Error; err != nil {
		return nil, err
	}

	return entitlements, nil
}

// GetEntitlementByFile returns entitlement for a specific file in an IPSW
func (s *Sqlite) GetEntitlementByFile(ipswID, filePath string) (*model.Entitlement, error) {
	var entitlement model.Entitlement
	if err := s.db.Preload("Keys").Where("ipsw_id = ? AND file_path = ?", ipswID, filePath).First(&entitlement).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &entitlement, nil
}

// Set sets the value for the given key.
// It overwrites any previous value for that key.
func (s *Sqlite) Save(value any) error {
	if result := s.db.Save(value); result.Error != nil {
		return result.Error
	}
	return nil
}

// Delete removes the given key.
// It returns ErrNotFound if the key does not exist.
func (s *Sqlite) Delete(key string) error {
	s.db.Delete(&model.Ipsw{}, key)
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

// GetDB returns the underlying GORM database instance
func (s *Sqlite) GetDB() *gorm.DB {
	return s.db
}
