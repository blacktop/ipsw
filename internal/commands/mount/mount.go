// Package mount provides the mount command
package mount

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
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

func dmgInIPSW(
	path, typ string, cfg *Config, attach attachFunc, decrypt decryptFunc,
) (*Context, error) {
	ipswPath := filepath.Clean(path)

	var i *info.Info
	var err error
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

	a := &imageAttempt{cfg: cfg, attach: attach, decrypt: decrypt}
	return a.acquire(typ, func() (string, error) { return a.extractByName(ipswPath, dmgPath) })
}

// DmgComponentInIPSW mounts one exact BuildManifest archive path. Callers must
// provide a private extraction directory and release the context before removing it.
func DmgComponentInIPSW(ipswPath, component string, cfg *Config) (*Context, error) {
	a := &imageAttempt{cfg: cfg, attach: utils.MountDMG, decrypt: aea.Decrypt}
	return a.mountComponent(ipswPath, component)
}

// ExactArchiveMember returns the single regular archive member named name.
func ExactArchiveMember(zr *zip.Reader, name string) (*zip.File, error) {
	var member *zip.File
	matches := 0
	for _, file := range zr.File {
		if file.Name == name && !file.FileInfo().IsDir() {
			member = file
			matches++
		}
	}
	if matches != 1 {
		return nil, fmt.Errorf("component %q requires one exact archive member, found %d", name, matches)
	}
	return member, nil
}

type attachFunc func(string, string) (utils.DMGMount, error)
type decryptFunc func(*aea.DecryptConfig) (string, error)

// imageAttempt is one acquisition of a backing image. It records every file it
// creates so a failed attempt removes those and never a pre-existing file.
type imageAttempt struct {
	cfg     *Config
	attach  attachFunc
	decrypt decryptFunc
	created []string
}

// acquire extracts, prepares, and attaches an image. A session can own cleanup
// only after acquisition succeeds; until then this attempt removes its files.
func (a *imageAttempt) acquire(
	typ string, extract func() (string, error),
) (ctx *Context, err error) {
	defer func() {
		if ctx != nil {
			return
		}
		for _, path := range a.created {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("failed to remove extracted image %s: %w", path, removeErr))
			}
		}
	}()
	extractedDMG, err := extract()
	if err != nil {
		return nil, err
	}
	return a.mount(extractedDMG, typ)
}

func (a *imageAttempt) mountComponent(ipswPath, component string) (*Context, error) {
	return a.acquire("", func() (string, error) { return a.extractExactMember(ipswPath, component) })
}

// extractByName reuses an image already extracted under dmgPath, otherwise it
// extracts the archive member whose base name matches dmgPath.
func (a *imageAttempt) extractByName(ipswPath, dmgPath string) (string, error) {
	extractDir := a.cfg.ExtractDir
	if extractDir == "" {
		extractDir = os.TempDir()
	}
	extractedDMG := filepath.Join(extractDir, dmgPath)
	if _, err := os.Stat(extractedDMG); !os.IsNotExist(err) {
		return extractedDMG, nil
	}
	a.created = append(a.created, extractedDMG)
	dmgs, err := utils.Unzip(ipswPath, extractDir, func(f *zip.File) bool {
		return strings.EqualFold(filepath.Base(f.Name), dmgPath)
	})
	if err != nil {
		return "", fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
	}
	if len(dmgs) == 0 {
		return "", fmt.Errorf("failed to find %s in IPSW", dmgPath)
	}
	return extractedDMG, nil
}

// extractExactMember writes the single archive member named component into
// the private extraction directory. It never reuses or replaces a file there.
func (a *imageAttempt) extractExactMember(ipswPath, component string) (string, error) {
	if a.cfg.ExtractDir == "" || !filepath.IsLocal(component) {
		return "", errors.New("exact component mount requires a private extraction directory " +
			"and relative component path")
	}
	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	member, err := ExactArchiveMember(&zr.Reader, component)
	if err != nil {
		return "", err
	}
	extractedDMG := filepath.Join(a.cfg.ExtractDir, filepath.Base(component))
	if filepath.Ext(extractedDMG) == ".aea" {
		// AEA decryption writes beside the member and would replace this file.
		decryptedDMG := strings.TrimSuffix(extractedDMG, filepath.Ext(extractedDMG))
		if _, err := os.Lstat(decryptedDMG); !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("component decryption output %s already exists", decryptedDMG)
		}
	}
	if err := writeArchiveMember(member, extractedDMG); err != nil {
		return "", err
	}
	a.created = append(a.created, extractedDMG)
	return extractedDMG, nil
}

// writeArchiveMember creates dst exclusively, so a concurrent writer of the
// same path fails instead of truncating an image another attempt is using.
func writeArchiveMember(member *zip.File, dst string) error {
	src, err := member.Open()
	if err != nil {
		return fmt.Errorf("failed to open %s in IPSW: %w", member.Name, err)
	}
	defer src.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create component image: %w", err)
	}
	_, err = io.Copy(out, src)
	err = errors.Join(err, out.Close())
	if err != nil {
		err = fmt.Errorf("failed to extract %s from IPSW: %w", member.Name, err)
		return errors.Join(err, os.Remove(dst))
	}
	return nil
}

// mount decrypts or unwraps an extracted image as needed and attaches it.
func (a *imageAttempt) mount(extractedDMG, typ string) (*Context, error) {
	extractedDMG, err := a.decryptAEA(extractedDMG)
	if err != nil {
		return nil, err
	}
	if err := decryptDMG(extractedDMG, a.cfg.Keys); err != nil {
		return nil, err
	}
	if typ == "rdisk" {
		if err := unwrapRamdisk(extractedDMG); err != nil {
			return nil, err
		}
	}
	m, err := a.attach(extractedDMG, a.cfg.MountPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %s: %v", extractedDMG, err)
	}
	return &Context{
		DmgPath:        extractedDMG,
		MountPoint:     m.MountPoint,
		AlreadyMounted: m.AlreadyMounted,
		OwnsDirectory:  m.OwnsDirectory,
		RetainDmg:      !slices.Contains(a.created, extractedDMG),
	}, nil
}

func (a *imageAttempt) decryptAEA(encryptedDMG string) (string, error) {
	if filepath.Ext(encryptedDMG) != ".aea" {
		return encryptedDMG, nil
	}
	decryptedDMG := strings.TrimSuffix(encryptedDMG, filepath.Ext(encryptedDMG))
	if _, statErr := os.Stat(decryptedDMG); os.IsNotExist(statErr) {
		a.created = append(a.created, decryptedDMG)
	}
	decrypted, err := a.decrypt(&aea.DecryptConfig{
		Input:    encryptedDMG,
		Output:   filepath.Dir(encryptedDMG),
		PemDB:    a.cfg.PemDB,
		Proxy:    "",    // TODO: make proxy configurable
		Insecure: false, // TODO: make insecure configurable
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
	}
	if slices.Contains(a.created, encryptedDMG) {
		_ = os.Remove(encryptedDMG)
	}
	return decrypted, nil
}

func decryptDMG(path string, keys any) error {
	isEncrypted, err := magic.IsEncryptedDMG(path)
	if err != nil {
		return fmt.Errorf("failed to check if DMG is encrypted: %v", err)
	}
	if !isEncrypted {
		return nil
	}
	var key string
	switch v := keys.(type) {
	case string:
		key = v
	case download.WikiFWKeys:
		key, err = v.GetKeyByFilename(path)
		if err != nil {
			return fmt.Errorf("failed to get key for DMG '%s': %v", path, err)
		}
	}
	log.Info("Decrypting DMG...")
	d, err := dmg.Open(path, &dmg.Config{Key: key})
	if err != nil {
		return fmt.Errorf("failed to open DMG '%s': %v", path, err)
	}
	defer func() { _ = d.Close() }()
	if err := os.Rename(d.DecryptedTemp(), path); err != nil {
		return fmt.Errorf("failed to overwrite encrypted DMG with the decrypted one: %v", err)
	}
	return nil
}

// unwrapRamdisk replaces a ramdisk IM4P with its raw DMG payload.
func unwrapRamdisk(path string) error {
	im4p, err := img4.OpenPayload(path)
	if err != nil {
		return fmt.Errorf("failed to parse ramdisk IM4P: %v", err)
	}
	data, err := im4p.GetData()
	if err != nil {
		return fmt.Errorf("failed to get ramdisk IM4P data: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to overwrite ramdisk DMG: %v", err)
	}
	return nil
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
