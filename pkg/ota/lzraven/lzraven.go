// Package lzraven detects whether the host can decode LZRaven, the Apple
// Archive compression ("pbzm" streams) that macOS 27 OTAs use for payloadv2
// members and RIDIFF cryptex patches.
//
// ipsw has no LZRaven decoder of its own: it relies on the system aa tool and
// libParallelCompression, which only gained LZRaven in macOS 27. Older hosts
// reject pbzm streams in aa and can crash inside libParallelCompression, so
// callers check before handing them one.
package lzraven

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/execabs"
)

// Magic is the stream magic of LZRaven-compressed Apple Archive data.
const Magic = "pbzm"

// ridiffHeaderScan bounds how far into a RIDIFF patch the inner compression
// magic is searched for; it sits at offset 0x3e or 0x46 in observed patches.
const ridiffHeaderScan = 256

// ErrUnsupported reports that the host cannot decode LZRaven streams.
var ErrUnsupported = errors.New(
	"this OTA uses LZRaven (pbzm) compression, which this host cannot decode; " +
		"extract it on macOS 27 or newer")

// probe is a minimal Apple Archive written with `aa archive -a lzraven`.
//
//go:embed probe.aar
var probe []byte

// CheckHost returns nil when the system aa tool decodes LZRaven, and an error
// wrapping [ErrUnsupported] otherwise.
func CheckHost() error {
	aaPath, err := execabs.LookPath("aa")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	cmd := exec.Command(aaPath, "list")
	cmd.Stdin = bytes.NewReader(probe)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: aa failed to read an LZRaven sample: %v: %s",
			ErrUnsupported, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CheckStream checks the host when the stream starting with header is
// LZRaven-compressed.
func CheckStream(header []byte) error {
	if !bytes.HasPrefix(header, []byte(Magic)) {
		return nil
	}
	return CheckHost()
}

// CheckRIDIFF checks the host when the RIDIFF patch at path wraps
// LZRaven-compressed data.
func CheckRIDIFF(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open RIDIFF patch %s: %w", path, err)
	}
	defer f.Close()
	header := make([]byte, ridiffHeaderScan)
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("failed to read RIDIFF patch header %s: %w", path, err)
	}
	if !bytes.Contains(header[:n], []byte(Magic)) {
		return nil
	}
	return CheckHost()
}
