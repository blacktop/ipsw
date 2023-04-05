// Package server contains the main server struct and methods
package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/api/server/route/download"
	"github.com/blacktop/ipsw/api/server/route/idev"
	"github.com/blacktop/ipsw/api/server/route/info"
	"github.com/blacktop/ipsw/api/server/route/ipsw"
	"github.com/blacktop/ipsw/api/server/route/kernel"
	"github.com/blacktop/ipsw/api/server/route/macho"
	"github.com/blacktop/ipsw/api/server/route/system"
	"github.com/gin-gonic/gin"
)

// Config is the server config
type Config struct {
	Host   string
	Port   int
	Socket string
	Debug  bool
}

// Server is the main server struct
type Server struct {
	router *gin.Engine
	server *http.Server
	conf   *Config
}

// NewServer creates a new server
func NewServer(conf *Config) *Server {
	return &Server{
		router: gin.Default(),
		conf:   conf,
	}
}

// Start starts the server
func (s *Server) Start() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rg := s.router.Group("/api/v1")
	download.AddRoutes(rg)
	macho.AddRoutes(rg)
	kernel.AddRoutes(rg)
	idev.AddRoutes(rg)
	info.AddRoutes(rg)
	ipsw.AddRoutes(rg)
	system.AddRoutes(rg)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.conf.Port),
		Handler: s.router,
	}

	go func() {
		if len(s.conf.Socket) > 0 {
			l, err := net.Listen("unix", filepath.Clean(s.conf.Socket))
			if err != nil {
				log.Fatalf("server: failed to listen: %v\n", err)
			}
			if err := s.server.Serve(l); err != nil && err != http.ErrServerClosed {
				log.Fatalf("server: failed to serve: %v\n", err)
			}
		} else {
			if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("server: failed to listen and serve: %v\n", err)
			}
		}
		s.Stop()
	}()

	// Listen for the interrupt signal.
	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()

	log.Warn("Shutting down gracefully: Press Ctrl+C again to force")

	return s.Stop()
}

// Stop stops the server
func (s *Server) Stop() error {
	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %v", err)
	}

	log.Info("Server Exiting")

	return nil
}
