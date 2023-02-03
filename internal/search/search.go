package search

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
)

func scanDmg(ipswPath, dmgPath, dmgType string, handler func(string, *macho.File) error) error {
	// check if filesystem DMG already exists (due to previous mount command)
	if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
		dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
			return strings.EqualFold(filepath.Base(f.Name), dmgPath)
		})
		if err != nil {
			return fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
		}
		if len(dmgs) == 0 {
			return fmt.Errorf("failed to find %s in IPSW", dmgPath)
		}
		defer os.Remove(dmgs[0])
	} else {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Found extracted %s", dmgPath))
	}
	utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting %s %s", dmgType, dmgPath))
	mountPoint, alreadyMounted, err := utils.MountFS(dmgPath)
	if err != nil {
		return fmt.Errorf("failed to mount DMG: %v", err)
	}
	if alreadyMounted {
		utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Unmount(mountPoint, false); err != nil {
				log.Errorf("failed to unmount DMG at %s: %v", dmgPath, err)
			}
		}()
	}

	var files []string
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
	}

	for _, file := range files {
		if m, err := macho.Open(file); err == nil {
			if err := handler(strings.TrimPrefix(file, mountPoint), m); err != nil {
				return fmt.Errorf("failed to handle macho %s: %v", file, err)
			}
			m.Close()
		}
	}

	return nil
}

func ForEachMachoInIPSW(ipswPath string, handler func(string, *macho.File) error) error {

	i, err := info.Parse(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW: %v", err)
	}

	if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
		log.Info("Scanning filesystem")
		if err := scanDmg(ipswPath, fsOS, "filesystem", handler); err != nil {
			return fmt.Errorf("failed to scan files in filesystem %s: %v", fsOS, err)
		}
	}
	if systemOS, err := i.GetSystemOsDmg(); err == nil {
		log.Info("Scanning SystemOS")
		if err := scanDmg(ipswPath, systemOS, "SystemOS", handler); err != nil {
			return fmt.Errorf("failed to scan files in SystemOS %s: %v", systemOS, err)
		}
	}
	if appOS, err := i.GetAppOsDmg(); err == nil {
		log.Info("Scanning AppOS")
		if err := scanDmg(ipswPath, appOS, "AppOS", handler); err != nil {
			return fmt.Errorf("failed to scan files in AppOS %s: %v", appOS, err)
		}
	}

	return nil
}
