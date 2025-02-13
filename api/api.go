// Package api contains common constants for daemon and client.
package api

// FIXME: this doesn't work with Go 1.24 currently and errors: panic: unsupported version: 2
////go:generate swagger generate spec -o swagger.json

// Common constants for daemon and client.
const (
	// DefaultVersion of Current REST API
	DefaultVersion = "1"
)
