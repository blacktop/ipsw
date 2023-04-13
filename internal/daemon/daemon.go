// Package daemon provides the daemon interface and implementation.
package daemon

import (
	"github.com/blacktop/ipsw/api/server"
	"github.com/blacktop/ipsw/internal/config"
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
	conf   *config.Config
}

// NewDaemon creates a new daemon.
func NewDaemon() Daemon {
	return &daemon{}
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
	})
	return d.server.Start()
}

func (d *daemon) Stop() error {
	return d.server.Stop()
}
