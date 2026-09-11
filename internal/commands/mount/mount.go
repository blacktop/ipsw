// Package mount provides the mount command
package mount

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
)

var DmgTypes = []string{"app", "sys", "fs", "exc", "rdisk", "rosetta"}

// Config contains optional options for mounting a DMG from an IPSW
type Config struct {
	Device string // Product type or device class to select DMGs for
	// Info is pre-parsed IPSW metadata (BuildManifest, DeviceTrees). When set
	// the IPSW is not parsed again, so callers mounting several volumes of one
	// IPSW decode it once. Device is still applied to it.
	Info *info.Info
	// SelectSystemOS optionally chooses an image by index when no Device is set
	// and the manifest contains multiple SystemOS images. Nil rejects ambiguity.
	SelectSystemOS func([]info.SystemOSDMG) (int, error)
	PemDB          string // AEA PEM DB JSON file path (for .aea decryption)
	Keys           any    // Either string (DMG key) or download.WikiFWKeys (auto-lookup)
	MountPoint     string // Custom mount point
	Ident          string // BuildManifest identity selector (used for rdisk)
	// ExtractDir is where DMGs are extracted/decrypted (default: os.TempDir()).
	// Callers that also mount the same volumes via internal/search.scanDmg (which
	// extracts to the cwd) set this to the cwd so both share one backing file and
	// the same volume is never attached twice.
	ExtractDir string
}

// Context is the mount context
type Context struct {
	MountPoint     string `json:"mount_point" binding:"required"`
	DmgPath        string `json:"dmg_path,omitempty"` // FIXME: required on linux
	AlreadyMounted bool   `json:"already_mounted,omitempty"`
	OwnsDirectory  bool   `json:"owns_directory,omitempty"`
	// RetainDmg is set when the backing image existed before this acquisition.
	// It is serialized so an unmount driven by the /mount API response keeps
	// the same ownership decision.
	RetainDmg bool `json:"retain_dmg,omitempty"`
	// Remember successful detach independently of later file cleanup failures.
	// Release and Close may both attempt cleanup on this context.
	detached bool
}

// Unmount detaches a DMG and removes its backing file unless acquisition reused
// a pre-existing file. A zero-value Context always removes the file.
func (c *Context) Unmount() error {
	if !c.detached {
		if info, err := utils.MountInfo(); err == nil { // darwin only
			if image := info.Mount(c.MountPoint); image != nil {
				c.DmgPath = filepath.Clean(image.ImagePath)
			}
		}
	}
	m := utils.DMGMount{MountPoint: c.MountPoint, AlreadyMounted: c.AlreadyMounted, OwnsDirectory: c.OwnsDirectory}
	return c.unmount(func() error { return m.Unmount(true) })
}

func (c *Context) unmount(detach func() error) error {
	if c.detached {
		return c.removeBackingFile()
	}
	if err := utils.Retry(3, 2*time.Second, func() error {
		err := detach()
		if err == nil {
			c.detached = true
		}
		return err
	}); err != nil {
		return fmt.Errorf("%w: failed to unmount %s at %s: %v", utils.ErrMountCleanup, c.DmgPath, c.MountPoint, err)
	}
	return c.removeBackingFile()
}

// removeBackingFile runs only after the image has been detached successfully.
func (c Context) removeBackingFile() error {
	if c.RetainDmg {
		return nil
	}
	cleanDmgPath := filepath.Clean(c.DmgPath)
	if cleanDmgPath == "." || cleanDmgPath == "" {
		return nil
	}
	return utils.Retry(3, 1*time.Second, func() error {
		if err := os.Remove(cleanDmgPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		return nil
	})
}

// DmgInIPSW will mount a DMG from an IPSW
func DmgInIPSW(path, typ string, cfg *Config) (*Context, error) {
	return dmgInIPSW(path, typ, cfg, utils.MountDMG, aea.Decrypt)
}

func dmgInIPSW(path, typ string, cfg *Config, attach func(string, string) (utils.DMGMount, error), decrypt func(*aea.DecryptConfig) (string, error)) (ctx *Context, err error) {
	// A session can own cleanup only after acquisition succeeds. Until then,
	// remove files created by this attempt without deleting pre-existing files.
	var created []string
	defer func() {
		if ctx != nil {
			return
		}
		for _, path := range created {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("failed to remove extracted image %s: %w", path, removeErr))
			}
		}
	}()

	ipswPath := filepath.Clean(path)

	var i *info.Info
	if cfg.Info != nil {
		i = cfg.Info
	} else if wkeys, ok := cfg.Keys.(download.WikiFWKeys); ok {
		dtkey, err := wkeys.GetKeyByRegex(`.*DeviceTree.*(img3|im4p)$`)
		if err != nil {
			return nil, fmt.Errorf("failed to get DeviceTree key: %v", err)
		}
		i, err = info.Parse(ipswPath, dtkey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPSW: %v", err)
		}
	} else {
		i, err = info.Parse(ipswPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IPSW: %v", err)
		}
	}

	i, err = i.ForDevice(cfg.Device)
	if err != nil {
		return nil, err
	}

	var dmgPath string

	switch typ {
	case "fs":
		dmgPath, err = i.GetFileSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to get filesystem DMG: %v", err)
		}
	case "sys":
		dmgPath, err = systemOSPath(i, cfg)
		if err != nil {
			if errors.Is(err, info.ErrorCryptexNotFound) {
				log.Warn("could not find SystemOS DMG; trying filesystem DMG (older IPSWs don't have cryptexes)")
				dmgPath, err = i.GetFileSystemOsDmg()
				if err != nil {
					return nil, fmt.Errorf("failed to get filesystem DMG: %v", err)
				}
			} else {
				return nil, fmt.Errorf("failed to get SystemOS DMG: %w", err)
			}
		}
	case "app":
		dmgPath, err = i.GetAppOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to get AppOS DMG: %v", err)
		}
	case "exc":
		dmgPath, err = i.GetExclaveOSDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to get ExclaveOS DMG: %v", err)
		}
	case "rdisk":
		dmgPath, err = i.GetRestoreRamDiskDmg(cfg.Ident)
		if err != nil {
			return nil, fmt.Errorf("failed to get RestoreRamDisk DMG: %v", err)
		}
	case "rosetta":
		dmgPath, err = i.GetRosettaOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to get RosettaOS DMG: %v", err)
		}
	default:
		return nil, fmt.Errorf("invalid subcommand: %s; must be one of: '%s'", typ, strings.Join(DmgTypes, "', '"))
	}

	extractDir := cfg.ExtractDir
	if extractDir == "" {
		extractDir = os.TempDir()
	}
	extractedDMG := filepath.Join(extractDir, dmgPath)

	if _, err := os.Stat(extractedDMG); os.IsNotExist(err) {
		created = append(created, extractedDMG)
		dmgs, err := utils.Unzip(ipswPath, extractDir, func(f *zip.File) bool {
			return strings.EqualFold(filepath.Base(f.Name), dmgPath)
		})
		if err != nil {
			return nil, fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
		}
		if len(dmgs) == 0 {
			return nil, fmt.Errorf("failed to find %s in IPSW", dmgPath)
		}
	}

	if filepath.Ext(extractedDMG) == ".aea" {
		encryptedDMG := extractedDMG
		decryptedDMG := strings.TrimSuffix(encryptedDMG, filepath.Ext(encryptedDMG))
		if _, statErr := os.Stat(decryptedDMG); os.IsNotExist(statErr) {
			created = append(created, decryptedDMG)
		}
		extractedDMG, err = decrypt(&aea.DecryptConfig{
			Input:    encryptedDMG,
			Output:   filepath.Dir(encryptedDMG),
			PemDB:    cfg.PemDB,
			Proxy:    "",    // TODO: make proxy configurable
			Insecure: false, // TODO: make insecure configurable
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
		}
		if slices.Contains(created, encryptedDMG) {
			_ = os.Remove(encryptedDMG)
		}
	}
	if isEncrypted, err := magic.IsEncryptedDMG(extractedDMG); err != nil {
		return nil, fmt.Errorf("failed to check if DMG is encrypted: %v", err)
	} else if isEncrypted {
		var key string
		switch v := cfg.Keys.(type) {
		case string:
			key = v
		case download.WikiFWKeys:
			key, err = v.GetKeyByFilename(extractedDMG)
			if err != nil {
				return nil, fmt.Errorf("failed to get key for DMG '%s': %v", extractedDMG, err)
			}
		}
		log.Info("Decrypting DMG...")
		if dmg, err := dmg.Open(extractedDMG, &dmg.Config{
			Key: key,
		}); err != nil {
			return nil, fmt.Errorf("failed to open DMG '%s': %v", extractedDMG, err)
		} else {
			defer func() { _ = dmg.Close() }()
			if err := os.Rename(dmg.DecryptedTemp(), extractedDMG); err != nil {
				return nil, fmt.Errorf("failed to overwrite encrypted DMG with the decrypted one: %v", err)
			}
		}
	}

	if typ == "rdisk" {
		// ramdisk DMGs are actually IM4P files
		im4p, err := img4.OpenPayload(extractedDMG)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ramdisk IM4P: %v", err)
		}
		data, err := im4p.GetData()
		if err != nil {
			return nil, fmt.Errorf("failed to get ramdisk IM4P data: %v", err)
		}
		// overwrite extractedDMG with the raw IM4P data
		if err := os.WriteFile(extractedDMG, data, 0644); err != nil {
			return nil, fmt.Errorf("failed to overwrite ramdisk DMG: %v", err)
		}
	}

	m, err := attach(extractedDMG, cfg.MountPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %s: %v", extractedDMG, err)
	}

	return &Context{
		DmgPath:        extractedDMG,
		MountPoint:     m.MountPoint,
		AlreadyMounted: m.AlreadyMounted,
		OwnsDirectory:  m.OwnsDirectory,
		RetainDmg:      !slices.Contains(created, extractedDMG),
	}, nil
}

func systemOSPath(i *info.Info, cfg *Config) (string, error) {
	if cfg.Device != "" || cfg.SelectSystemOS == nil {
		return i.GetSystemOsDmg()
	}
	dmgs, err := i.GetSystemOsDmgs()
	if err != nil {
		return "", err
	}
	if len(dmgs) == 1 {
		return dmgs[0].Path, nil
	}
	selected, err := cfg.SelectSystemOS(dmgs)
	if err != nil {
		return "", err
	}
	if selected < 0 || selected >= len(dmgs) {
		return "", fmt.Errorf("invalid SystemOS image selection: %d", selected)
	}
	return dmgs[selected].Path, nil
}
