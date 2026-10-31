package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/dustin/go-humanize"
)

func mountWithHFSPlus(image, mountPoint string) error {
	return mountHFSPlus(image, mountPoint, (*exec.Cmd).CombinedOutput)
}

func mountHFSPlus(image, mountPoint string, run func(*exec.Cmd) ([]byte, error)) error {
	raw, err := hfsPlusImage(image)
	if err != nil {
		return err
	}
	if raw != image {
		// The loop device keeps the opened file alive until unmount.
		defer os.Remove(raw)
	}
	// util-linux mount owns the loop device and marks it for automatic cleanup.
	// In particular, stderr from losetup can never become part of a device name.
	out, err := run(exec.Command("mount", "-t", "hfsplus", "-o", "ro,loop", raw, mountPoint))
	if err != nil {
		return fmt.Errorf("failed to mount HFS+ filesystem %q: %w: %s (ensure hfsplus kernel module is loaded)", image, err, out)
	}
	return nil
}

// hfsPlusImage returns a raw HFS+/HFSX image suitable for a Linux loop device.
// A UDIF container must be decoded even when its encryption has been removed.
// The caller owns the returned file only when its path differs from image.
func hfsPlusImage(image string) (string, error) {
	isDMG, err := magic.IsDMG(image)
	if err != nil {
		return "", err
	}
	if !isDMG {
		return image, nil
	}
	f, err := os.Open(image)
	if err != nil {
		return "", err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return "", err
	}
	var footer dmg.UDIFResourceFile
	footerSize := int64(binary.Size(footer))
	if stat.Size() < footerSize {
		return "", fmt.Errorf("HFS+ DMG is too short for its footer")
	}
	if err := binary.Read(io.NewSectionReader(f, stat.Size()-footerSize, footerSize), binary.BigEndian, &footer); err != nil {
		return "", fmt.Errorf("failed to read HFS+ DMG footer: %w", err)
	}
	// go-apfs currently exits the process for resource-fork-only images.
	// They cannot supply a block map supported by this conversion path.
	if footer.PlistOffset == 0 || footer.PlistLength == 0 {
		return "", fmt.Errorf("HFS+ DMG has no supported plist block map")
	}
	// Only the block maps are needed. Loading the GPT also creates a cache
	// whose capacity comes from the image's metadata.
	d, err := dmg.NewDMG(io.NewSectionReader(f, 0, stat.Size()))
	if err != nil {
		return "", fmt.Errorf("failed to open HFS+ DMG: %w", err)
	}
	var probeErrs []error
	for idx := range d.Partitions {
		part := &d.Partitions[idx]
		// Sequential reads only need the current decoded chunk.
		part.BuffersNeeded = 1
		var signature [2]byte
		if _, err := part.ReadAt(signature[:], 1024); err != nil {
			probeErrs = append(probeErrs, fmt.Errorf("partition %q: %w", part.Name, err))
			continue
		}
		if signature != [2]byte{'H', '+'} && signature != [2]byte{'H', 'X'} {
			continue
		}
		// go-apfs validates the partition sector count against the image size
		// and MaxInt64 before exposing it here.
		size := int64(part.SectorCount) * 512
		raw, err := createRawImage(image)
		if err != nil {
			return "", err
		}
		n, copyErr := io.Copy(raw, io.NewSectionReader(part, 0, size))
		if copyErr == nil && n != size {
			copyErr = io.ErrUnexpectedEOF
		}
		if err := errors.Join(copyErr, raw.Close()); err != nil {
			_ = os.Remove(raw.Name())
			hint := "free space beside the image"
			if filepath.Dir(raw.Name()) != filepath.Dir(image) {
				hint = "set TMPDIR to a larger filesystem"
			}
			return "", fmt.Errorf("failed to unpack %s HFS+ partition %q into %s (%s): %w",
				humanize.IBytes(uint64(size)), part.Name, filepath.Dir(raw.Name()), hint, err)
		}
		return raw.Name(), nil
	}
	if len(probeErrs) > 0 {
		return "", fmt.Errorf("no HFS+ partition found in DMG %q: %w", image, errors.Join(probeErrs...))
	}
	return "", fmt.Errorf("no HFS+ partition found in DMG %q", image)
}

// createRawImage stages the decoded filesystem beside the DMG, which already
// holds the compressed copy, and falls back to the temp dir when that
// directory is read-only.
func createRawImage(image string) (*os.File, error) {
	raw, err := os.CreateTemp(filepath.Dir(image), ".ipsw-hfsplus-*.img")
	if err == nil {
		return raw, nil
	}
	raw, tmpErr := os.CreateTemp("", "ipsw-hfsplus-*.img")
	if tmpErr != nil {
		return nil, errors.Join(err, tmpErr)
	}
	return raw, nil
}
