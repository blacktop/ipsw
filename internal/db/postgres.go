package db

import (
	"errors"
	"fmt"

	"github.com/blacktop/ipsw/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Postgres is a database that stores data in a Postgres database.
type Postgres struct {
	URL      string
	Host     string
	Port     string
	User     string
	Password string
	Database string
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
		BatchSize: batchSize,
	}, nil
}

// Connect connects to the database.
func (p *Postgres) Connect() (err error) {
	p.db, err = gorm.Open(postgres.Open(fmt.Sprintf(
		"host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		p.Host, p.Port, p.User, p.Database, p.Password,
	)), &gorm.Config{
		CreateBatchSize:        p.BatchSize,
		SkipDefaultTransaction: true,
		// Logger:                 logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect postgres database: %w", err)
	}
	return p.db.AutoMigrate(
		&model.Ipsw{},
		&model.Device{},
		&model.Kernelcache{},
		&model.DyldSharedCache{},
		&model.Macho{},
		&model.Symbol{},
	)
}

// Create creates a new entry in the database.
// It returns ErrAlreadyExists if the key already exists.
func (p *Postgres) Create(value any) error {
	if result := p.db.FirstOrCreate(value); result.Error != nil {
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
		Where("ipsws.version = ? AND ipsws.build_id = ? AND devices.name = ?", version, build, device).
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
	if err := p.db.Where("uuid = ?", uuid).First(&macho).Error; err != nil {
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

// Set sets the value for the given key.
// It overwrites any previous value for that key.
func (p *Postgres) Save(value any) error {
	if result := p.db.Save(value); result.Error != nil {
		return result.Error
	}
	return nil
}

// Delete removes the given key.
// It returns ErrNotFound if the key does not exist.
func (p *Postgres) Delete(key string) error {
	p.db.Delete(&model.Ipsw{}, key)
	return nil
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
