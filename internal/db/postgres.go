package db

import (
	"errors"
	"fmt"

	"github.com/blacktop/ipsw/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// Postgres is a database that stores data in a Postgres database.
type Postgres struct {
	URL      string
	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string // SSL mode for connection (disable, require, verify-ca, verify-full)
	// Config
	BatchSize int

	db *gorm.DB
}

// NewPostgres creates a new Postgres database.
func NewPostgres(host, port, user, password, database string, batchSize int) (Database, error) {
	if host == "" || port == "" || user == "" || database == "" {
		return nil, fmt.Errorf("'host', 'port', 'user' and 'database' are required")
	}
	return &Postgres{
		Host:      host,
		Port:      port,
		User:      user,
		Password:  password,
		Database:  database,
		SSLMode:   "disable", // Default to disable for local development
		BatchSize: batchSize,
	}, nil
}

// NewPostgresWithSSL creates a new Postgres database with SSL configuration.
func NewPostgresWithSSL(host, port, user, password, database, sslMode string, batchSize int) (Database, error) {
	if host == "" || port == "" || user == "" || database == "" {
		return nil, fmt.Errorf("'host', 'port', 'user' and 'database' are required")
	}
	if sslMode == "" {
		sslMode = "disable"
	}
	return &Postgres{
		Host:      host,
		Port:      port,
		User:      user,
		Password:  password,
		Database:  database,
		SSLMode:   sslMode,
		BatchSize: batchSize,
	}, nil
}

// Connect connects to the database.
func (p *Postgres) Connect() (err error) {
	// Use a connection string that disables prepared statements to avoid conflicts
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s password=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Database, p.Password, p.SSLMode,
	)
	
	p.db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true, // Use simple protocol to avoid prepared statements
	}), &gorm.Config{
		CreateBatchSize:        1000, // Larger batch size for bulk operations
		SkipDefaultTransaction: true,
		TranslateError:         true,
		PrepareStmt:            false, // Disable prepared statements to avoid conflicts
		Logger:                 logger.Default.LogMode(logger.Silent),
		// Performance optimizations for bulk operations
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return fmt.Errorf("failed to connect postgres database: %w", err)
	}
	// Check if we already have the main tables (they might have been created manually)
	var ipswTableCount int64
	err = p.db.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'ipsws' AND table_schema = CURRENT_SCHEMA()").Scan(&ipswTableCount).Error
	if err != nil {
		return fmt.Errorf("failed to check table existence: %w", err)
	}
	
	if ipswTableCount > 0 {
		// Main tables already exist, skip migration
		// This handles the case where tables were created manually via schema.sql
		return nil
	}
	
	// Tables don't exist, let GORM create them
	return p.db.AutoMigrate(
		&model.Ipsw{},
		&model.Device{},
		&model.Kernelcache{},
		&model.DyldSharedCache{},
		&model.Macho{},
		&model.Path{},
		&model.Symbol{},
		&model.Name{},
		// Entitlement models
		&model.EntitlementKey{},
		&model.EntitlementValue{},
		&model.Entitlement{},
	)
}

// Create creates a new entry in the database.
// It returns ErrAlreadyExists if the key already exists.
func (p *Postgres) Create(value any) error {
	if result := p.db.Create(value); result.Error != nil {
		return result.Error
	}
	return nil
}

// Get returns the value for the given key.
// It returns ErrNotFound if the key does not exist.
func (p *Postgres) Get(key string) (*model.Ipsw, error) {
	i := &model.Ipsw{}
	p.db.First(&i, key)
	return i, nil
}

// Get returns the value for the given key.
// It returns ErrNotFound if the key does not exist.
func (p *Postgres) GetIpswByName(name string) (*model.Ipsw, error) {
	i := &model.Ipsw{Name: name}
	if result := p.db.First(&i); result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, model.ErrNotFound
		}
		return nil, result.Error
	}
	return i, nil
}

func (p *Postgres) GetIPSW(version, build, device string) (*model.Ipsw, error) {
	var ipsw model.Ipsw
	if err := p.db.Joins("JOIN ipsw_devices ON ipsw_devices.ipsw_id = ipsws.id").
		Joins("JOIN devices ON devices.name = ipsw_devices.device_name").
		Where("ipsws.version = ? AND ipsws.buildid = ? AND devices.name = ?", version, build, device).
		First(&ipsw).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &ipsw, nil
}

func (p *Postgres) GetDSC(uuid string) (*model.DyldSharedCache, error) {
	var dsc model.DyldSharedCache
	if err := p.db.Where("uuid = ?", uuid).First(&dsc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &dsc, nil
}

func (p *Postgres) GetDSCImage(uuid string, address uint64) (*model.Macho, error) {
	var macho model.Macho
	if err := p.db.Joins("JOIN dsc_images ON dsc_images.macho_uuid = machos.uuid").
		Joins("JOIN dyld_shared_caches ON dyld_shared_caches.uuid = dsc_images.dyld_shared_cache_uuid").
		Joins("Path").
		Where("dyld_shared_caches.uuid = ? AND machos.text_start <= ? AND ? < machos.text_end", uuid, address, address).
		First(&macho).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &macho, nil
}

func (p *Postgres) GetMachO(uuid string) (*model.Macho, error) {
	var macho model.Macho
	if err := p.db.Preload("Path").Where("uuid = ?", uuid).First(&macho).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &macho, nil
}

func (p *Postgres) GetSymbol(uuid string, address uint64) (*model.Symbol, error) {
	var symbol model.Symbol
	if err := p.db.Joins("JOIN macho_syms ON macho_syms.symbol_id = symbols.id").
		Joins("JOIN machos ON machos.uuid = macho_syms.macho_uuid").
		Joins("Name").
		Where("machos.uuid = ? AND symbols.start <= ? AND ? < symbols.end", uuid, address, address).
		First(&symbol).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return &symbol, nil
}

func (p *Postgres) GetSymbols(uuid string) ([]*model.Symbol, error) {
	var syms []*model.Symbol
	if err := p.db.Joins("JOIN macho_syms ON macho_syms.symbol_id = symbols.id").
		Joins("JOIN machos ON machos.uuid = macho_syms.macho_uuid").
		Joins("Name").
		Where("machos.uuid = ?", uuid).
		Select("symbol", "start", "end").
		Find(&syms).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, model.ErrNotFound
		}
		return nil, err
	}
	return syms, nil
}

// Save sets the value for the given key.
// It overwrites any previous value for that key.
func (p *Postgres) Save(value any) error {
	// TODO: add rollback on error
	if ipsw, ok := value.(*model.Ipsw); ok {
		// Start transaction
		return p.db.Transaction(func(tx *gorm.DB) error {
			// Defer foreign key checks
			// if err := tx.Exec("SET CONSTRAINTS ALL DEFERRED").Error; err != nil {
			// 	return err
			// }
			// Process Paths
			if err := p.processPaths(tx, ipsw); err != nil {
				return err
			}
			// Process Names
			if err := p.processNames(tx, ipsw); err != nil {
				return err
			}
			// Save the main IPSW entry
			if err := tx.Save(ipsw).Error; err != nil {
				return fmt.Errorf("failed to save IPSW: %w", err)
			}

			return nil
		})
	}
	return fmt.Errorf("invalid value type: %T", value)
}

func (p *Postgres) processPaths(tx *gorm.DB, ipsw *model.Ipsw) error {
	uniquePaths := make(map[string]struct{})

	// Collect unique paths
	for _, kernel := range ipsw.Kernels {
		for _, kext := range kernel.Kexts {
			uniquePaths[kext.Path.Path] = struct{}{}
		}
	}
	for _, dsc := range ipsw.DSCs {
		for _, img := range dsc.Images {
			uniquePaths[img.Path.Path] = struct{}{}
		}
	}
	for _, fs := range ipsw.FileSystem {
		uniquePaths[fs.Path.Path] = struct{}{}
	}

	if len(uniquePaths) == 0 {
		return nil
	}

	// Process paths in batches
	paths := make([]string, 0, len(uniquePaths))
	for path := range uniquePaths {
		paths = append(paths, path)
	}

	for i := 0; i < len(paths); i += p.BatchSize {
		end := min(i+p.BatchSize, len(paths))
		batch := paths[i:end]

		// Bulk create or get Paths
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "path"}},
			DoNothing: true,
		}).Create(convertToPaths(batch)).Error; err != nil {
			return fmt.Errorf("failed to create paths: %w", err)
		}
	}

	// Fetch all created/existing Paths in batches
	var allPaths []model.Path
	for i := 0; i < len(paths); i += p.BatchSize {
		end := min(i+p.BatchSize, len(paths))
		batch := paths[i:end]

		var batchPaths []model.Path
		if err := tx.Where("path IN ?", batch).Find(&batchPaths).Error; err != nil {
			return fmt.Errorf("failed to fetch paths: %w", err)
		}
		allPaths = append(allPaths, batchPaths...)
	}

	// Create a map for quick Path lookup
	pathMap := make(map[string]*model.Path)
	for i := range allPaths {
		pathMap[allPaths[i].Path] = &allPaths[i]
	}

	// Update Path IDs
	for _, kernel := range ipsw.Kernels {
		for _, kext := range kernel.Kexts {
			kext.Path.ID = pathMap[kext.GetPath()].ID
		}
	}
	for _, dsc := range ipsw.DSCs {
		for _, img := range dsc.Images {
			img.Path.ID = pathMap[img.GetPath()].ID
		}
	}
	for _, fs := range ipsw.FileSystem {
		fs.Path.ID = pathMap[fs.GetPath()].ID
	}

	return nil
}

func (p *Postgres) processNames(tx *gorm.DB, ipsw *model.Ipsw) error {
	uniqueNames := make(map[string]struct{})

	// Collect unique names
	for _, kernel := range ipsw.Kernels {
		for _, kext := range kernel.Kexts {
			for _, sym := range kext.Symbols {
				uniqueNames[sym.GetName()] = struct{}{}
			}
		}
	}
	for _, dsc := range ipsw.DSCs {
		for _, img := range dsc.Images {
			for _, sym := range img.Symbols {
				uniqueNames[sym.GetName()] = struct{}{}
			}
		}
	}
	for _, fs := range ipsw.FileSystem {
		for _, sym := range fs.Symbols {
			uniqueNames[sym.GetName()] = struct{}{}
		}
	}

	if len(uniqueNames) == 0 {
		return nil
	}

	// Process names in batches
	names := make([]string, 0, len(uniqueNames))
	for name := range uniqueNames {
		names = append(names, name)
	}

	for i := 0; i < len(names); i += p.BatchSize {
		end := min(i+p.BatchSize, len(names))
		batch := names[i:end]

		// Bulk create or get Names
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "name"}},
			DoNothing: true,
		}).Create(convertToNames(batch)).Error; err != nil {
			return fmt.Errorf("failed to create names: %w", err)
		}
	}

	// Fetch all created/existing Names in batches
	var allNames []model.Name
	for i := 0; i < len(names); i += p.BatchSize {
		end := min(i+p.BatchSize, len(names))
		batch := names[i:end]

		var batchNames []model.Name
		if err := tx.Where("name IN ?", batch).Find(&batchNames).Error; err != nil {
			return fmt.Errorf("failed to fetch names: %w", err)
		}
		allNames = append(allNames, batchNames...)
	}

	// Create a map for quick Name lookup
	nameMap := make(map[string]*model.Name)
	for i := range allNames {
		nameMap[allNames[i].Name] = &allNames[i]
	}

	// Update Symbols with Name IDs
	for _, kernel := range ipsw.Kernels {
		for _, kext := range kernel.Kexts {
			for _, sym := range kext.Symbols {
				sym.Name.ID = nameMap[sym.GetName()].ID
			}
		}
	}
	for _, dsc := range ipsw.DSCs {
		for _, img := range dsc.Images {
			for _, sym := range img.Symbols {
				sym.Name.ID = nameMap[sym.GetName()].ID
			}
		}
	}
	for _, fs := range ipsw.FileSystem {
		for _, sym := range fs.Symbols {
			sym.Name.ID = nameMap[sym.GetName()].ID
		}
	}

	return nil
}

func convertToPaths(paths []string) []model.Path {
	result := make([]model.Path, len(paths))
	for i, path := range paths {
		result[i] = model.Path{Path: path}
	}
	return result
}

func convertToNames(names []string) []model.Name {
	result := make([]model.Name, len(names))
	for i, name := range names {
		result[i] = model.Name{Name: name}
	}
	return result
}

// Delete removes the given key.
// It returns ErrNotFound if the key does not exist.
func (p *Postgres) Delete(key string) error {
	p.db.Delete(&model.Ipsw{}, key)
	return nil
}

// GetDB returns the underlying GORM database instance.
func (p *Postgres) GetDB() *gorm.DB {
	return p.db
}

// Close closes the database.
// It returns ErrClosed if the database is already closed.
func (p *Postgres) Close() error {
	db, err := p.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
