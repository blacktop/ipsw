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
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
)

var DmgTypes = []string{"fs", "sys", "app", "exc"}

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
	// TODO: check if DmgPath is safe before removing (should be in /tmp and should be src of mount)
	return os.Remove(filepath.Clean(c.DmgPath))
}

// DmgInIPSW will mount a DMG from an IPSW
func DmgInIPSW(path, typ, pemDbPath string) (*Context, error) {
	ipswPath := filepath.Clean(path)

	i, err := info.Parse(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPSW: %v", err)
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
		defer os.Remove(extractedDMG) // remove the encrypted AEA DMG decrypting and mounting
		extractedDMG, err = aea.Decrypt(&aea.DecryptConfig{
			Input:  extractedDMG,
			Output: filepath.Dir(extractedDMG),
			PemDB:  pemDbPath,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
		}
	}

	mp, am, err := utils.MountDMG(extractedDMG)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %s: %v", extractedDMG, err)
	}

	return &Context{
		DmgPath:        extractedDMG,
		MountPoint:     mp,
		AlreadyMounted: am,
	}, nil
}
