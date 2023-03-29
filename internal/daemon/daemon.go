// Package daemon provides the daemon interface and implementation.
package daemon

import "github.com/blacktop/ipsw/api/server"

// Daemon is the interface that describes an ipsw daemon.
type Daemon interface {
	// Start starts the daemon.
	Start() error
	// Stop stops the daemon.
	Stop() error
}

type daemon struct {
	server *server.Server
}

// NewDaemon creates a new daemon.
func NewDaemon() Daemon {
	return &daemon{}
}

func (d *daemon) Start() error {
	d.server = server.NewServer()
	return d.server.Start()
}

func (d *daemon) Stop() error {
	return d.server.Stop()
}
