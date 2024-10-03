package syms

import (
	"context"
	"database/sql"
	"testing"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
)

func TestScan(t *testing.T) {
	ctx := context.Background()

	dsn := "postgres://blacktop:@localhost:5432/postgres?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))

	db := bun.NewDB(sqldb, pgdialect.New())
	db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
	defer db.Close()

	db.AddQueryHook(bundebug.NewQueryHook(
		bundebug.WithVerbose(true),
		bundebug.FromEnv("BUNDEBUG"),
	))

	// Register models for the ORM
	db.RegisterModel(
		(*model.IpswToDevice)(nil),
		(*model.IpswToKernelcache)(nil),
		(*model.IpswToDyldSharedCache)(nil),
		(*model.IpswToMacho)(nil),
		(*model.KernelcacheToMacho)(nil),
		(*model.DyldSharedCacheToMacho)(nil),
		(*model.MachoToSymbol)(nil),
	)

	// Create tables
	err := createSchema(db)
	assert.NoError(t, err)

	// Create devices
	device1 := &model.Device{
		Name: "iPhone14,3",
	}

	device2 := &model.Device{
		Name: "iPhone14,2",
	}

	// Create kernelcaches
	kernelcache1 := &model.Kernelcache{
		UUID:    types.UUID{1},
		Version: "Version1",
	}

	kernelcache2 := &model.Kernelcache{
		UUID:    types.UUID{2},
		Version: "Version2",
	}

	// Create dyld shared caches
	dsc1 := &model.DyldSharedCache{
		UUID:              types.UUID{3},
		SharedRegionStart: 0x180000000,
	}

	dsc2 := &model.DyldSharedCache{
		UUID:              types.UUID{4},
		SharedRegionStart: 0x190000000,
	}

	// Create Mach-O files
	macho1 := &model.Macho{
		UUID: types.UUID{5},
		Path: model.Path{Path: "/usr/bin/test1"},
	}

	macho2 := &model.Macho{
		UUID: types.UUID{6},
		Path: model.Path{Path: "/usr/bin/test2"},
	}

	// Create the Ipsw
	ipsw := &model.Ipsw{
		SHA256:  "fake-sha256",
		Name:    "iOS 16.0",
		Version: "16.0",
		BuildID: "20A5328h",
		Devices: []model.Device{*device1, *device2},
		Kernels: []model.Kernelcache{*kernelcache1, *kernelcache2},
		DSCs:    []model.DyldSharedCache{*dsc1, *dsc2},
		// Assume FileSystem is a slice of Machos
		FileSystem: []model.Macho{*macho1, *macho2},
	}

	// Insert Ipsw
	_, err = db.NewInsert().Model(ipsw).Exec(ctx)
	assert.NoError(t, err)

	// Insert relations
	for _, device := range ipsw.Devices {
		_, err = db.NewInsert().Model(&device).On("CONFLICT (name) DO NOTHING").Exec(ctx)
		assert.NoError(t, err)

		relation := &model.IpswToDevice{
			IpswID:   ipsw.ID,
			DeviceID: device.ID,
		}
		_, err = db.NewInsert().Model(relation).Exec(ctx)
		assert.NoError(t, err)
	}

	for _, kernel := range ipsw.Kernels {
		_, err = db.NewInsert().Model(&kernel).On("CONFLICT (uuid) DO NOTHING").Exec(ctx)
		assert.NoError(t, err)

		relation := &model.IpswToKernelcache{
			IpswID:        ipsw.ID,
			KernelcacheID: kernel.ID,
		}
		_, err = db.NewInsert().Model(relation).Exec(ctx)
		assert.NoError(t, err)
	}

	for _, dsc := range ipsw.DSCs {
		_, err = db.NewInsert().Model(&dsc).On("CONFLICT (uuid) DO NOTHING").Exec(ctx)
		assert.NoError(t, err)

		relation := &model.IpswToDyldSharedCache{
			IpswID:            ipsw.ID,
			DyldSharedCacheID: dsc.ID,
		}
		_, err = db.NewInsert().Model(relation).Exec(ctx)
		assert.NoError(t, err)
	}

	for _, macho := range ipsw.FileSystem {
		_, err = db.NewInsert().Model(&macho).On("CONFLICT (uuid) DO NOTHING").Exec(ctx)
		assert.NoError(t, err)

		relation := &model.IpswToMacho{
			IpswID:  ipsw.ID,
			MachoID: macho.ID,
		}
		_, err = db.NewInsert().Model(relation).Exec(ctx)
		assert.NoError(t, err)
	}

	// Retrieve the Ipsw with relations
	ipswOut := new(model.Ipsw)
	err = db.NewSelect().
		Model(ipswOut).
		Relation("Devices").
		Relation("Kernels").
		Relation("DSCs").
		Relation("FileSystem").
		Where("i.sha256 = ?", ipsw.SHA256).
		Scan(ctx)
	assert.NoError(t, err)
	assert.Equal(t, ipsw.Name, ipswOut.Name)
	assert.Equal(t, len(ipsw.Devices), len(ipswOut.Devices))

	// Update the Ipsw Name
	ipswOut.Name = "iOS 16.0 Updated"
	_, err = db.NewUpdate().Model(ipswOut).WherePK().Exec(ctx)
	assert.NoError(t, err)

	// Verify the update
	ipswUpdated := new(model.Ipsw)
	err = db.NewSelect().
		Model(ipswUpdated).
		Where("id = ?", ipswOut.ID).
		Scan(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "iOS 16.0 Updated", ipswUpdated.Name)

	// Remove a Device
	_, err = db.NewDelete().
		Model((*model.IpswToDevice)(nil)).
		Where("ipsw_id = ? AND device_id = ?", ipsw.ID, device1.ID).
		Exec(ctx)
	assert.NoError(t, err)

	// Verify the Device removal
	ipswOut = new(model.Ipsw)
	err = db.NewSelect().
		Model(ipswOut).
		Relation("Devices").
		Where("i.id = ?", ipsw.ID).
		Scan(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ipswOut.Devices))
	assert.Equal(t, device2.Name, ipswOut.Devices[0].Name)
}

// Helper functions for setting up the database

func createSchema(db *bun.DB) error {
	models := []interface{}{
		(*model.Ipsw)(nil),
		(*model.Device)(nil),
		(*model.Kernelcache)(nil),
		(*model.DyldSharedCache)(nil),
		(*model.Macho)(nil),
		(*model.IpswToDevice)(nil),
		(*model.IpswToKernelcache)(nil),
		(*model.IpswToDyldSharedCache)(nil),
		(*model.IpswToMacho)(nil),
		(*model.KernelcacheToMacho)(nil),
	}

	for _, model := range models {
		_, err := db.NewCreateTable().
			Model(model).
			IfNotExists().
			WithForeignKeys().
			Exec(context.Background())
		if err != nil {
			return err
		}
	}
	return nil
}
