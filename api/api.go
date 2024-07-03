// Package api contains common constants for daemon and client.
package api

//go:generate go run github.com/go-swagger/go-swagger/cmd/swagger generate spec -o swagger.json --scan-models

// Common constants for daemon and client.
const (
	// DefaultVersion of Current REST API
	DefaultVersion = "1"
)
