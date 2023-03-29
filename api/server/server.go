// Package server contains the main server struct and methods
package server

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/api/server/route/download"
	"github.com/gin-gonic/gin"
)

// Server is the main server struct
type Server struct {
	router *gin.Engine
	server *http.Server
}

// NewServer creates a new server
func NewServer() *Server {
	return &Server{
		router: gin.Default(),
	}
}

// Start starts the server
func (s *Server) Start() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rg := s.router.Group("/api/v1")
	download.AddRoutes(rg)

	s.server = &http.Server{
		Addr:    ":8080",
		Handler: s.router,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ipsw server failed to listen: %v\n", err)
		}
	}()

	// Listen for the interrupt signal.
	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	log.Info("shutting down gracefully, press Ctrl+C again to force")

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

	log.Info("Server exiting")

	return nil
}
