// Package server contains the main server struct and methods
package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Server is the main server struct
type Server struct {
	router *gin.Engine
}

// NewServer creates a new server
func NewServer() *Server {
	return &Server{
		router: gin.Default(),
	}
}

// Start starts the server
func (s *Server) Start() error {
	s.router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	return s.router.Run(":8080")
}

// Stop stops the server
func (s *Server) Stop() error {
	return nil
}
