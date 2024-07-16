// Package daemon provides the daemon interface and implementation.
package daemon

import (
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/api/server"
	"github.com/blacktop/ipsw/internal/config"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/gin-gonic/gin"
)

// Daemon is the interface that describes an ipsw daemon.
type Daemon interface {
	// Start starts the daemon.
	Start() error
	// Stop stops the daemon.
	Stop() error
}

type daemon struct {
	server *server.Server
	db     db.Database
	conf   *config.Config
}

// NewDaemon creates a new daemon.
func NewDaemon() Daemon {
	return &daemon{}
}

func (d *daemon) setupDB() (err error) {
	switch d.conf.Database.Driver {
	case "sqlite":
		d.db, err = db.NewSqlite(d.conf.Database.Path, d.conf.Database.BatchSize)
		if err != nil {
			return fmt.Errorf("failed to create sqlite database: %w", err)
		}
		return d.db.Connect()
	case "postgres":
		d.db, err = db.NewPostgres(
			d.conf.Database.Host,
			d.conf.Database.Port,
			d.conf.Database.User,
			d.conf.Database.Password,
			d.conf.Database.Name,
			d.conf.Database.BatchSize,
		)
		if err != nil {
			return fmt.Errorf("failed to create postgres database: %w", err)
		}
		return d.db.Connect()
	case "memory":
		d.db, err = db.NewInMemory(d.conf.Database.Path)
		if err != nil {
			return fmt.Errorf("failed to create in-memory database: %w", err)
		}
		return d.db.Connect()
	default:
		if d.conf.Database.Driver != "" {
			return fmt.Errorf("unsupported database driver: '%s'", d.conf.Database.Driver)
		}
	}
	log.Debug("daemon start: no database")
	return nil
}

func (d *daemon) Start() (err error) {
	d.conf, err = config.LoadConfig()
	if err != nil {
		return err
	}
	if d.conf.Daemon.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	d.server = server.NewServer(&server.Config{
		Host:    d.conf.Daemon.Host,
		Port:    d.conf.Daemon.Port,
		Socket:  d.conf.Daemon.Socket,
		Debug:   d.conf.Daemon.Debug,
		LogFile: d.conf.Daemon.LogFile,
		PemDB:   d.conf.Daemon.PemDB,
		SigsDir: d.conf.Daemon.SigsDir,
	})
	if err := d.setupDB(); err != nil {
		return err
	}
	return d.server.Start(d.db)
}

func (d *daemon) Stop() error {
	if err := d.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %v", err)
	}
	return d.server.Stop()
}
