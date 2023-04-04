// Package daemon provides the daemon interface and implementation.
package daemon

import (
	"github.com/blacktop/ipsw/api/server"
	"github.com/gin-gonic/gin"
)

// Daemon is the interface that describes an ipsw daemon.
type Daemon interface {
	// Start starts the daemon.
	Start() error
	// Stop stops the daemon.
	Stop() error
}

// Config is the daemon config.
type Config struct {
	Debug bool
}

type daemon struct {
	server *server.Server
	conf   *Config
}

// NewDaemon creates a new daemon.
func NewDaemon(conf *Config) Daemon {
	return &daemon{conf: conf}
}

func (d *daemon) Start() error {
	if d.conf.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	d.server = server.NewServer(&server.Config{
		Debug: d.conf.Debug,
	})
	return d.server.Start()
}

func (d *daemon) Stop() error {
	return d.server.Stop()
}
