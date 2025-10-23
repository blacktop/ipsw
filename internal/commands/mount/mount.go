// Package mount provides the mount command
package mount

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

var DmgTypes = []string{"fs", "sys", "app", "exc", "rdisk"}

// Config contains optional options for mounting a DMG from an IPSW
type Config struct {
	PemDB      string // AEA PEM DB JSON file path (for .aea decryption)
	Keys       any    // Either string (DMG key) or download.WikiFWKeys (auto-lookup)
	MountPoint string // Custom mount point
	Ident      string // BuildManifest identity selector (used for rdisk)
}

// Context is the mount context
type Context struct {
	MountPoint     string `json:"mount_point" binding:"required"`
	DmgPath        string `json:"dmg_path,omitempty"` // FIXME: required on linux
	AlreadyMounted bool   `json:"already_mounted,omitempty"`
}

// Unmount will unmount a DMG and remove the DMG source file
func (c Context) Unmount() error {
	if info, err := utils.MountInfo(); err == nil { // darwin only
		if image := info.Mount(c.MountPoint); image != nil {
			c.DmgPath = filepath.Clean(image.ImagePath)
		}
	}
	if err := utils.Retry(3, 2*time.Second, func() error {
		return utils.Unmount(c.MountPoint, true)
	}); err != nil {
		return fmt.Errorf("failed to unmount %s at %s: %v", c.DmgPath, c.MountPoint, err)
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
	var err error

	ipswPath := filepath.Clean(path)

	var i *info.Info
	if wkeys, ok := cfg.Keys.(download.WikiFWKeys); ok {
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

	var dmgPath string

	switch typ {
	case "fs":
		dmgPath, err = i.GetFileSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to get filesystem DMG: %v", err)
		}
	case "sys":
		dmgPath, err = i.GetSystemOsDmg()
		if err != nil {
			if errors.Is(err, info.ErrorCryptexNotFound) {
				log.Warn("could not find SystemOS DMG; trying filesystem DMG (older IPSWs don't have cryptexes)")
				dmgPath, err = i.GetFileSystemOsDmg()
				if err != nil {
					return nil, fmt.Errorf("failed to get filesystem DMG: %v", err)
				}
			} else {
				return nil, fmt.Errorf("failed to get SystemOS DMG: %v", err)
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
		if len(cfg.Ident) > 0 {
			dmgPath, err = i.GetRestoreRamDiskDmgByIdent(cfg.Ident)
			if err != nil {
				return nil, fmt.Errorf("failed to get RestoreRamDisk DMG: %v", err)
			}
		} else {
			// Prefer Erase -> Update -> first
			if p, err := i.GetRestoreRamDiskDmgByIdent("Erase"); err == nil {
				dmgPath = p
			} else if p, err := i.GetRestoreRamDiskDmgByIdent("Update"); err == nil {
				dmgPath = p
			} else {
				if dmgs, err := i.GetRestoreRamDiskDmgs(); err == nil {
					if len(dmgs) == 0 {
						return nil, fmt.Errorf("no RestoreRamDisk DMG found")
					}
					dmgPath = dmgs[0]
				} else {
					return nil, fmt.Errorf("failed to get RestoreRamDisk DMGs: %v", err)
				}
			}
		}
	default:
		return nil, fmt.Errorf("invalid subcommand: %s; must be one of: '%s'", typ, strings.Join(DmgTypes, "', '"))
	}

	extractedDMG := filepath.Join(os.TempDir(), dmgPath)

	if _, err := os.Stat(extractedDMG); os.IsNotExist(err) {
		dmgs, err := utils.Unzip(ipswPath, os.TempDir(), func(f *zip.File) bool {
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
		defer func() {
			_ = os.Remove(extractedDMG) // remove the encrypted AEA DMG after decrypting and mounting
		}()
		extractedDMG, err = aea.Decrypt(&aea.DecryptConfig{
			Input:    extractedDMG,
			Output:   filepath.Dir(extractedDMG),
			PemDB:    cfg.PemDB,
			Insecure: false, // TODO: make insecure configurable
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
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

	mp, am, err := utils.MountDMG(extractedDMG, cfg.MountPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %s: %v", extractedDMG, err)
	}

	return &Context{
		DmgPath:        extractedDMG,
		MountPoint:     mp,
		AlreadyMounted: am,
	}, nil
}
