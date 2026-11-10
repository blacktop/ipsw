// Package fairplay provides local application decryption helpers.
package fairplay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	authorizationHeaderBytes = 22
	// AuthorizationMaxBytes bounds a serialized local authorization snapshot.
	AuthorizationMaxBytes = (16 << 20) + authorizationHeaderBytes
	offlinePathMax        = 4096
	parentSyncUnconfirmed = 1
)

var authorizationMagic = []byte{'F', 'P', 'A', 'U', 'T', 'H', 0, 0}

var (
	ErrOfflineUnavailable = errors.New("offline decryption is unavailable in this build")
	ErrOfflineABI         = errors.New("offline engine ABI is incompatible")
	ErrOfflineArgument    = errors.New("invalid offline operation argument")
	ErrLicenseAbsent      = errors.New("matching license record was not found")
	ErrOfflineUnsupported = errors.New("platform or input format is not supported")
	ErrOfflinePermission  = errors.New("authorization access or file permissions were rejected")
	ErrOfflineIO          = errors.New("offline operation could not read or write its files")
	ErrOfflineProcessing  = errors.New("offline processing failed")
	// ErrOfflinePanic reports ABI status 7. The caller must retire the process
	// without retrying; an opaque panic payload is quarantined until exit.
	ErrOfflinePanic  = errors.New("offline engine encountered an internal failure")
	ErrOfflineBuffer = errors.New("authorization capture buffer is too small")
)

// Result describes successful offline publication.
type Result struct {
	// ParentSyncUnconfirmed means publication succeeded without confirmed directory durability.
	ParentSyncUnconfirmed bool
}

// ValidAuthorization checks the snapshot envelope; the contents remain opaque.
func ValidAuthorization(data []byte) bool {
	return len(data) > authorizationHeaderBytes && len(data) <= AuthorizationMaxBytes &&
		bytes.Equal(data[:8], authorizationMagic) &&
		binary.BigEndian.Uint32(data[8:12]) == 1 &&
		uint64(binary.BigEndian.Uint32(data[12:16])) == uint64(len(data)-authorizationHeaderBytes)
}

// OfflineAvailable checks whether this build has a compatible offline engine.
// It does not read authorization files or start a service.
func OfflineAvailable() error { return offlineAvailable() }

// DecryptIPA runs the whole offline IPA pipeline using an explicit authorization
// file. output must be a new directory; existing output is never overwritten.
// After ErrOfflinePanic, the caller must retire the process without retrying.
func DecryptIPA(ipa, authorization, output string) (Result, error) {
	for _, path := range []string{ipa, authorization, output} {
		if path == "" || len(path) > offlinePathMax || strings.ContainsRune(path, 0) {
			return Result{}, ErrOfflineArgument
		}
	}
	return offlineDecrypt(ipa, authorization, output)
}

// CaptureAuthorization returns a bounded opaque snapshot of existing local
// authorization. Privileged callers must use a short-lived helper process.
// This function never changes process credentials or writes an output file.
// After ErrOfflinePanic, the caller must retire the process without retrying.
func CaptureAuthorization() ([]byte, error) { return offlineCapture() }

func offlineStatus(status int32) error {
	switch status {
	case 0:
		return nil
	case 1:
		return ErrOfflineArgument
	case 2:
		return ErrLicenseAbsent
	case 3:
		return ErrOfflineUnsupported
	case 4:
		return ErrOfflinePermission
	case 5:
		return ErrOfflineIO
	case 6:
		return ErrOfflineProcessing
	case 7:
		return ErrOfflinePanic
	case 8:
		return ErrOfflineBuffer
	default:
		return fmt.Errorf("offline engine returned an unknown status (%d)", status)
	}
}
