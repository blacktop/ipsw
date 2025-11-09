package search

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/ftab"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
)

// DmgInfo provides a name/path pair for a DMG contained in an IPSW.
type DmgInfo struct {
	Name string
	Path string
}

// ListDMGs returns known DMGs in a stable order.
// Why: call sites often need the same enumeration.
func ListDMGs(ipswPath string) ([]DmgInfo, error) {
	i, err := info.Parse(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPSW: %v", err)
	}
	var dmgs []DmgInfo
	if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
		dmgs = append(dmgs, DmgInfo{"FileSystem", fsOS})
	}
	if systemOS, err := i.GetSystemOsDmg(); err == nil {
		dmgs = append(dmgs, DmgInfo{"SystemOS", systemOS})
	}
	if appOS, err := i.GetAppOsDmg(); err == nil {
		dmgs = append(dmgs, DmgInfo{"AppOS", appOS})
	}
	if excOS, err := i.GetExclaveOSDmg(); err == nil {
		dmgs = append(dmgs, DmgInfo{"ExclaveOS", excOS})
	}
	return dmgs, nil
}

// ScanAllDMGs runs handlers across files in every DMG.
// If betweenHandlers != nil, fire it after each handler (per DMG) for TUIs.
func ScanAllDMGs(ipswPath, pemDB string, betweenHandlers func(int), handlers ...func(string, string) error) error {
	dmgs, err := ListDMGs(ipswPath)
	if err != nil {
		return err
	}
	for _, d := range dmgs {
		if betweenHandlers != nil {
			if err := ScanDmgWithMultipleHandlersAndCallback(ipswPath, d.Path, d.Name, pemDB, betweenHandlers, handlers...); err != nil {
				return fmt.Errorf("failed to scan %s: %w", d.Name, err)
			}
		} else {
			if err := ScanDmgWithMultipleHandlers(ipswPath, d.Path, d.Name, pemDB, handlers...); err != nil {
				return fmt.Errorf("failed to scan %s: %w", d.Name, err)
			}
		}
	}
	return nil
}

// ScanDmgWithMultipleHandlers mounts once and runs multiple handlers per file.
// Why: multi-pass scans without repeated mounts.
func ScanDmgWithMultipleHandlers(ipswPath, dmgPath, dmgType, pemDB string, handlers ...func(string, string) error) error {
	return scanDmgMulti(ipswPath, dmgPath, dmgType, pemDB, handlers, nil)
}

// ScanDmgWithMultipleHandlersAndCallback also runs a callback after each pass.
// Why: TUIs can publish totals/state between passes.
func ScanDmgWithMultipleHandlersAndCallback(ipswPath, dmgPath, dmgType, pemDB string, betweenHandlers func(int), handlers ...func(string, string) error) error {
	return scanDmgMulti(ipswPath, dmgPath, dmgType, pemDB, handlers, betweenHandlers)
}

// scanDmgMulti is the shared engine behind the helpers above.
func scanDmgMulti(ipswPath, dmgPath, dmgType, pemDB string, handlers []func(string, string) error, betweenHandlers func(int)) error {
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
			Input:    dmgPath,
			Output:   filepath.Dir(dmgPath),
			PemDB:    pemDB,
			Proxy:    "",    // TODO: make proxy configurable
			Insecure: false, // TODO: make insecure configurable
		})
		if err != nil {
			return fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
		}
		defer os.Remove(dmgPath)
	}
	utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting %s %s", dmgType, dmgPath))
	mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath, "")
	if err != nil {
		return fmt.Errorf("failed to mount DMG: %v", err)
	}
	if alreadyMounted {
		utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, true)
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
			// Skip paths with permission errors gracefully
			if os.IsPermission(err) {
				log.Debugf("skipping path due to permission denied: %s", path)
				return nil
			}
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
						// Avoid adding duplicate file paths discovered via symlinks
						if !visited[subPath] {
							visited[subPath] = true
							files = append(files, subPath)
						}
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

	// Run all handlers on the same file list (single mount)
	for i, handler := range handlers {
		for _, file := range files {
			if err := func() error {
				return handler(mountPoint, file)
			}(); err != nil {
				return err
			}
		}
		// Let caller update UI/state between passes
		if betweenHandlers != nil {
			betweenHandlers(i)
		}
	}

	return nil
}

// scanDmg mounts a DMG and runs a single handler across files.
// Why: simple case; multi-pass should use ScanDmgWithMultipleHandlers.
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
			Input:    dmgPath,
			Output:   filepath.Dir(dmgPath),
			PemDB:    pemDB,
			Proxy:    "",    // TODO: make proxy configurable
			Insecure: false, // TODO: make insecure configurable
		})
		if err != nil {
			return fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
		}
		defer os.Remove(dmgPath)
	}
	utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting %s %s", dmgType, dmgPath))
	mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath, "")
	if err != nil {
		return fmt.Errorf("failed to mount DMG: %v", err)
	}
	if alreadyMounted {
		utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, true)
			}); err != nil {
				log.Errorf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err)
			}
		}()
	}

	var files []string
	// Track visited to avoid loops/duplicates (symlinks)
	visited := make(map[string]bool)
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Ignore permission errors
			if os.IsPermission(err) {
				log.Debugf("skipping path due to permission denied: %s", path)
				return nil
			}
			log.Errorf("failed to walk mount %s: %v", path, err)
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 { // follow symlinked dirs
			// Resolve symlink target
			if linkPath, err := filepath.EvalSymlinks(path); err == nil {
				// Stat target
				info, err = os.Stat(linkPath)
				if err != nil {
					return err
				}
				// Recurse once per target
				if info.IsDir() && !visited[linkPath] {
					visited[linkPath] = true
					return filepath.Walk(linkPath, func(subPath string, subInfo os.FileInfo, subErr error) error {
						if subErr != nil {
							log.WithError(subErr).Error("failed to walk symlinked path")
							return nil
						}
						// De-dupe discovered files via visited
						if !visited[subPath] {
							visited[subPath] = true
							files = append(files, subPath)
						}
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
		log.Info("Scanning FileSystem")
		if err := scanDmg(ipswPath, fsOS, "filesystem", pemDbPath, scanMacho); err != nil {
			return fmt.Errorf("failed to scan files in FileSystem %s: %w", fsOS, err)
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
			// Skip paths with permission errors gracefully
			if os.IsPermission(err) {
				log.Debugf("skipping path due to permission denied: %s", path)
				return nil
			}
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

	for _, im4pFile := range im4ps {
		if regexp.MustCompile(`armfw_.*.im4p$`).MatchString(im4pFile) {
			im4p, err := img4.OpenPayload(im4pFile)
			if err != nil {
				return fmt.Errorf("failed to open im4p file %s: %v", im4pFile, err)
			}
			im4pData, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get data from im4p file %s: %v", im4pFile, err)
			}
			ftab, err := ftab.Parse(bytes.NewReader(im4pData))
			if err != nil {
				return fmt.Errorf("failed to parse ftab: %v", err)
			}
			for _, entry := range ftab.Entries {
				data, err := io.ReadAll(entry)
				if err != nil {
					return fmt.Errorf("failed to read ftab entry: %v", err)
				}
				if m, err := macho.NewFile(bytes.NewReader(data)); err == nil {
					name := "agx_" + filepath.Base(string(entry.Tag[:]))
					if err := handler(name, m); err != nil {
						return fmt.Errorf("failed to handle macho %s: %v", name, err)
					}
				}
			}
			ftab.Close()
		} else if regexp.MustCompile(`.*exclavecore_bundle.*im4p$`).MatchString(im4pFile) {
			im4p, err := img4.OpenPayload(im4pFile)
			if err != nil {
				return fmt.Errorf("failed to open im4p file %s: %v", im4pFile, err)
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get data from im4p file %s: %v", im4pFile, err)
			}
			out, err := fwcmd.ExtractExclaveCores(data, os.TempDir())
			if err != nil {
				return fmt.Errorf("failed to split exclave apps FW: %v", err)
			}
			for _, f := range out {
				if m, err := macho.Open(f); err == nil {
					if err := handler("exclave_"+filepath.Base(f), m); err != nil {
						return fmt.Errorf("failed to handle macho %s: %v", f, err)
					}
					m.Close()
				}
			}
		} else {
			im4p, err := img4.OpenPayload(im4pFile)
			if err != nil {
				return fmt.Errorf("failed to open im4p file %s: %v", im4pFile, err)
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get data from im4p file %s: %v", im4pFile, err)
			}
			if m, err := macho.NewFile(bytes.NewReader(data)); err == nil {
				if err := handler(filepath.Base(im4pFile), m); err != nil {
					return fmt.Errorf("failed to handle macho %s: %v", im4pFile, err)
				}
				m.Close()
			} else {
				log.Debugf("failed to parse %s data as macho: %v", im4pFile, err)
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
		log.Info("Scanning FileSystem")
		if err := scanDmg(ipswPath, fsOS, "filesystem", pemDB, scanPlist); err != nil {
			return fmt.Errorf("failed to scan files in FileSystem %s: %w", fsOS, err)
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

func ForEachFileInIPSW(ipswPath, directory, pemDB string, handler func(string, string) error) error {
	i, err := info.Parse(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW: %v", err)
	}

	var dmg string
	scanFile := func(mountPoint, filePath string) error {
		// filter to only scan a specific directory (if provided)
		if directory != "" && !strings.Contains(filePath, directory) {
			return nil
		}
		if _, rest, ok := strings.Cut(filePath, mountPoint); ok {
			filePath = rest
		}
		if err := handler(dmg, filePath); err != nil {
			return fmt.Errorf("failed to handle file %s: %w", filePath, err)
		}
		return nil
	}

	// scan the IPSW as a zip file
	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to open IPSW: %v", err)
	}
	defer zr.Close()
	dmg = "IPSW"
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// skip DMGs/cryptexes as they always have a different name (i.e. 090-43228-337.dmg.aea)
		if regexp.MustCompile(`[0-9]{3}-[0-9]{5}-[0-9]{3}\.dmg(\.aea|\.trustcache)?(\.root_hash|\.trustcache|.integrity_catalog|\.mtree)?$`).MatchString(f.Name) {
			continue
		}
		if err := scanFile("", f.Name); err != nil {
			return fmt.Errorf("failed to scan file %s: %w", f.Name, err)
		}
	}
	// scan the IPSW's DMGs/cryptexes
	if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
		log.Info("Scanning FileSystem")
		dmg = "filesystem"
		if err := scanDmg(ipswPath, fsOS, dmg, pemDB, scanFile); err != nil {
			return fmt.Errorf("failed to scan files in FileSystem %s: %w", fsOS, err)
		}
	}
	if systemOS, err := i.GetSystemOsDmg(); err == nil {
		log.Info("Scanning SystemOS")
		dmg = "SystemOS"
		if err := scanDmg(ipswPath, systemOS, dmg, pemDB, scanFile); err != nil {
			return fmt.Errorf("failed to scan files in SystemOS %s: %w", systemOS, err)
		}
	}
	if appOS, err := i.GetAppOsDmg(); err == nil {
		log.Info("Scanning AppOS")
		dmg = "AppOS"
		if err := scanDmg(ipswPath, appOS, dmg, pemDB, scanFile); err != nil {
			return fmt.Errorf("failed to scan files in AppOS %s: %w", appOS, err)
		}
	}
	if excOS, err := i.GetExclaveOSDmg(); err == nil {
		log.Info("Scanning ExclaveOS")
		dmg = "ExclaveOS"
		if err := scanDmg(ipswPath, excOS, dmg, pemDB, scanFile); err != nil {
			return fmt.Errorf("failed to scan files in ExclaveOS %s: %w", excOS, err)
		}
	}

	return nil
}
