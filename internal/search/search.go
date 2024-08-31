package search

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	icmd "github.com/blacktop/ipsw/internal/commands/img4"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
)

// TODO: make this an array of handlers to perform multiple actions on each file
func scanDmg(ipswPath, dmgPath, dmgType, pemDB string, handler func(string, string) error) error {
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
	if filepath.Ext(dmgPath) == ".aea" {
		var err error
		dmgPath, err = aea.Decrypt(&aea.DecryptConfig{
			Input:  dmgPath,
			Output: filepath.Dir(dmgPath),
			PemDB:  pemDB,
		})
		if err != nil {
			return fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
		}
		defer os.Remove(dmgPath)
	}
	utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting %s %s", dmgType, dmgPath))
	mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath)
	if err != nil {
		return fmt.Errorf("failed to mount DMG: %v", err)
	}
	if alreadyMounted {
		utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, false)
			}); err != nil {
				log.Errorf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err)
			}
		}()
	}

	var files []string
	// Use a map to keep track of visited directories to avoid infinite loops
	visited := make(map[string]bool)
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("failed to walk mount %s: %v", path, err)
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 { // follow symlinks
			// Resolve the symlink
			if linkPath, err := filepath.EvalSymlinks(path); err == nil {
				// Get the info of the target file/directory
				info, err = os.Stat(linkPath)
				if err != nil {
					return err
				}
				// If it's a directory and not visited, follow it
				if info.IsDir() && !visited[linkPath] {
					visited[linkPath] = true
					return filepath.Walk(linkPath, func(subPath string, subInfo os.FileInfo, subErr error) error {
						if subErr != nil {
							log.WithError(subErr).Error("failed to walk symlinked path")
							return nil
						}
						files = append(files, subPath)
						return nil
					})
				}
			}
		} else {
			if !info.IsDir() {
				if !visited[path] {
					visited[path] = true
					files = append(files, path)
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
	}

	for _, file := range files {
		if err := func() error {
			return handler(mountPoint, file)
		}(); err != nil {
			return err
		}
	}

	return nil
}

// ForEachMachoInIPSW walks the IPSW and calls the handler for each macho file found
func ForEachMachoInIPSW(ipswPath, pemDbPath string, handler func(string, *macho.File) error) error {
	scanMacho := func(mountPoint, machoPath string) error {
		if ok, _ := magic.IsMachO(machoPath); ok {
			var m *macho.File
			// UNIVERSAL MACHO
			if fat, err := macho.OpenFat(machoPath); err == nil {
				defer fat.Close()
				m = fat.Arches[len(fat.Arches)-1].File
			} else { // SINGLE MACHO
				if errors.Is(err, macho.ErrNotFat) {
					m, err = macho.Open(machoPath)
					if err != nil {
						return nil
					}
					defer m.Close()
				} else { // NOT a macho file
					return nil
				}
			}
			if _, rest, ok := strings.Cut(machoPath, mountPoint); ok {
				machoPath = rest
			}
			if err := handler(machoPath, m); err != nil {
				return fmt.Errorf("failed to handle macho %s: %w", machoPath, err)
			}
		}
		return nil
	}

	i, err := info.Parse(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW: %v", err)
	}

	if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
		log.Info("Scanning filesystem")
		if err := scanDmg(ipswPath, fsOS, "filesystem", pemDbPath, scanMacho); err != nil {
			return fmt.Errorf("failed to scan files in filesystem %s: %w", fsOS, err)
		}
	}
	if systemOS, err := i.GetSystemOsDmg(); err == nil {
		log.Info("Scanning SystemOS")
		if err := scanDmg(ipswPath, systemOS, "SystemOS", pemDbPath, scanMacho); err != nil {
			return fmt.Errorf("failed to scan files in SystemOS %s: %w", systemOS, err)
		}
	}
	if appOS, err := i.GetAppOsDmg(); err == nil {
		log.Info("Scanning AppOS")
		if err := scanDmg(ipswPath, appOS, "AppOS", pemDbPath, scanMacho); err != nil {
			return fmt.Errorf("failed to scan files in AppOS %s: %w", appOS, err)
		}
	}
	if excOS, err := i.GetExclaveOSDmg(); err == nil {
		log.Info("Scanning ExclaveOS")
		if err := scanDmg(ipswPath, excOS, "ExclaveOS", pemDbPath, scanMacho); err != nil {
			return fmt.Errorf("failed to scan files in ExclaveOS %s: %w", excOS, err)
		}
	}

	return nil
}

// ForEachMacho walks the folder and calls the handler for each macho file found
func ForEachMacho(folder string, handler func(string, *macho.File) error) error {
	var files []string
	// Use a map to keep track of visited directories to avoid infinite loops
	visited := make(map[string]bool)
	if err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("failed to walk mount %s: %v", path, err)
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 { // follow symlinks
			// Resolve the symlink
			if linkPath, err := filepath.EvalSymlinks(path); err == nil {
				// Get the info of the target file/directory
				info, err = os.Stat(linkPath)
				if err != nil {
					return err
				}
				// If it's a directory and not visited, follow it
				if info.IsDir() && !visited[linkPath] {
					visited[linkPath] = true
					return filepath.Walk(linkPath, func(subPath string, subInfo os.FileInfo, subErr error) error {
						if subErr != nil {
							log.WithError(subErr).Error("failed to walk symlinked path")
							return nil
						}
						files = append(files, subPath)
						return nil
					})
				}
			}
		} else {
			if !info.IsDir() {
				if !visited[path] {
					visited[path] = true
					files = append(files, path)
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk files in dir %s: %v", folder, err)
	}

	for _, file := range files {
		if ok, _ := magic.IsMachO(file); ok {
			var m *macho.File
			// UNIVERSAL MACHO
			if fat, err := macho.OpenFat(file); err == nil {
				defer fat.Close()
				m = fat.Arches[len(fat.Arches)-1].File
			} else { // SINGLE MACHO
				if errors.Is(err, macho.ErrNotFat) {
					m, err = macho.Open(file)
					if err != nil {
						return nil
					}
					defer m.Close()
				} else { // NOT a macho file
					return nil
				}
			}
			if err := handler(file, m); err != nil {
				return fmt.Errorf("failed to handle macho %s: %w", file, err)
			}
		}
	}

	return nil
}

// ForEachIm4pInIPSW walks the IPSW and calls the handler for each im4p firmware macho file found
func ForEachIm4pInIPSW(ipswPath string, handler func(string, *macho.File) error) error {
	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_im4p")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory to store im4ps: %v", err)
	}
	defer os.RemoveAll(tmpDIR)

	im4ps, err := utils.Unzip(ipswPath, tmpDIR, func(f *zip.File) bool {
		return filepath.Ext(f.Name) == ".im4p"
	})
	if err != nil {
		return fmt.Errorf("failed to unzip im4p: %v", err)
	}

	for _, im4p := range im4ps {
		if err := icmd.ExtractPayload(im4p, im4p, false); err != nil {
			return fmt.Errorf("failed to extract im4p payload: %v", err)
		}
		if regexp.MustCompile(`armfw_.*.im4p$`).MatchString(im4p) {
			out, err := fwcmd.SplitGpuFW(im4p, os.TempDir())
			if err != nil {
				return fmt.Errorf("failed to split GPU FW: %v", err)
			}
			for _, f := range out {
				if m, err := macho.Open(f); err == nil {
					if err := handler("agx_"+filepath.Base(f), m); err != nil {
						return fmt.Errorf("failed to handle macho %s: %v", f, err)
					}
					m.Close()
				}
			}
		} else {
			if m, err := macho.Open(im4p); err == nil {
				if err := handler(filepath.Base(im4p), m); err != nil {
					return fmt.Errorf("failed to handle macho %s: %v", im4p, err)
				}
				m.Close()
			}
		}
	}

	return nil
}

func ForEachPlistInIPSW(ipswPath, directory, pemDB string, handler func(string, string) error) error {
	i, err := info.Parse(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW: %v", err)
	}

	scanPlist := func(mountPoint, plistPath string) error {
		// filter to only scan a specific directory (if provided)
		if directory != "" && !strings.Contains(plistPath, directory) {
			return nil
		}
		if strings.HasSuffix(plistPath, ".plist") {
			// settings := make(map[string]interface{})
			data, err := os.ReadFile(plistPath)
			if err != nil {
				return fmt.Errorf("failed to read plist %s: %v", plistPath, err)
			}
			// TODO: add support for binary plists
			// pdata, err := plist.MarshalIndent(data, plist.XMLFormat, "  ")
			// if err != nil {
			// 	return fmt.Errorf("failed to marshal plist %s: %v", plistPath, err)
			// }
			// if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&settings); err != nil {
			// 	return fmt.Errorf("failed to decode plist %s: %v", plistPath, err)
			// }
			// jdata, err := json.MarshalIndent(settings, "", "  ")
			// if err != nil {
			// 	return fmt.Errorf("failed to marshal plist %s: %v", plistPath, err)
			// }
			if _, rest, ok := strings.Cut(plistPath, mountPoint); ok {
				plistPath = rest
			}
			plistPath, err = filepath.Rel(directory, plistPath)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %v", plistPath, err)
			}
			if err := handler(plistPath, string(data)); err != nil {
				return fmt.Errorf("failed to handle plist %s: %v", plistPath, err)
			}
		}
		return nil
	}

	if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
		log.Info("Scanning filesystem")
		if err := scanDmg(ipswPath, fsOS, "filesystem", pemDB, scanPlist); err != nil {
			return fmt.Errorf("failed to scan files in filesystem %s: %w", fsOS, err)
		}
	}
	if systemOS, err := i.GetSystemOsDmg(); err == nil {
		log.Info("Scanning SystemOS")
		if err := scanDmg(ipswPath, systemOS, "SystemOS", pemDB, scanPlist); err != nil {
			return fmt.Errorf("failed to scan files in SystemOS %s: %w", systemOS, err)
		}
	}
	if appOS, err := i.GetAppOsDmg(); err == nil {
		log.Info("Scanning AppOS")
		if err := scanDmg(ipswPath, appOS, "AppOS", pemDB, scanPlist); err != nil {
			return fmt.Errorf("failed to scan files in AppOS %s: %w", appOS, err)
		}
	}
	if excOS, err := i.GetExclaveOSDmg(); err == nil {
		log.Info("Scanning ExclaveOS")
		if err := scanDmg(ipswPath, excOS, "ExclaveOS", pemDB, scanPlist); err != nil {
			return fmt.Errorf("failed to scan files in ExclaveOS %s: %w", excOS, err)
		}
	}

	return nil
}
