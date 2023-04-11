// Package mount provides the mount command
package mount

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

var dmgTypes = []string{"fs", "sys", "app"}

// Context is the mount context
type Context struct {
	DmgPath        string `json:"dmg_path" binding:"required"`
	MountPoint     string `json:"mount_point" binding:"required"`
	AlreadyMounted bool   `json:"already_mounted,omitempty"`
}

// Unmount will unmount a DMG and remove the DMG source file
func (c Context) Unmount() error {
	if err := utils.Retry(3, 2*time.Second, func() error {
		return utils.Unmount(c.MountPoint, false)
	}); err != nil {
		return fmt.Errorf("failed to unmount %s at %s: %v", c.DmgPath, c.MountPoint, err)
	}
	return os.Remove(c.DmgPath)
}

// DmgInIPSW will mount a DMG from an IPSW
func DmgInIPSW(path, typ string) (*Context, error) {
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
			return nil, fmt.Errorf("failed to get SystemOS DMG: %v", err)
		}
	case "app":
		dmgPath, err = i.GetAppOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to get AppOS DMG: %v", err)
		}
	default:
		return nil, fmt.Errorf("invalid subcommand: %s; must be one of: '%s'", typ, strings.Join(dmgTypes, "', '"))
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

	mp, am, err := utils.MountFS(extractedDMG)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %s: %v", extractedDMG, err)
	}

	return &Context{
		DmgPath:        extractedDMG,
		MountPoint:     mp,
		AlreadyMounted: am,
	}, nil
}
