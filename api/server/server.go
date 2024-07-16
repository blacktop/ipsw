// Package server ipswd API
//
// This allows you to interact with <code>ipsw</code> in a VERY powerful and flexible way via a RESTful API.
//
// The <code>ipswd</code> design was heavily influenced by the design of dockerd. So many of the same concepts apply.
//
//	Schemes: http
//	Host: localhost:3993
//	BasePath: /v1
//	Version: v1.0
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
// swagger:meta
package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/api"
	"github.com/blacktop/ipsw/api/server/routes"
	"github.com/blacktop/ipsw/api/server/routes/aea"
	"github.com/blacktop/ipsw/api/server/routes/syms"
	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/gin-gonic/gin"
)

// Config is the server config
type Config struct {
	Host    string
	Port    int
	Socket  string
	Debug   bool
	LogFile string
	PemDB   string
	SigsDir string
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
func (s *Server) Start(db db.Database) error {
	if s.conf.Debug {
		log.SetLevel(log.DebugLevel)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if len(s.conf.LogFile) > 0 {
		f, err := os.Create(s.conf.LogFile)
		if err != nil {
			return fmt.Errorf("server: failed to create log file: %v", err)
		}
		gin.DefaultWriter = io.MultiWriter(f, os.Stdout)
	}

	s.router.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, types.Version{
			APIVersion:     api.DefaultVersion,
			OSType:         runtime.GOOS,
			BuilderVersion: types.BuildVersion,
		})
	})

	rg := s.router.Group("/v" + api.DefaultVersion)

	routes.Add(rg, s.conf.PemDB)

	if db != nil {
		syms.AddRoutes(rg, db, s.conf.PemDB, s.conf.SigsDir)
	}

	if s.conf.PemDB != "" {
		aea.AddRoutes(rg, s.conf.PemDB)
	}

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
