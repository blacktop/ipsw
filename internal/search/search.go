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

var (
	reArmFwIm4p         = regexp.MustCompile(`armfw_.*.im4p$`)
	reExclaveBundleIm4p = regexp.MustCompile(`.*exclavecore_bundle.*im4p$`)
	reDmgAeaFile        = regexp.MustCompile(`[0-9]{3}-[0-9]{5}-[0-9]{3}\.dmg(\.aea|\.trustcache)?(\.root_hash|\.trustcache|\.integrity_catalog|\.mtree)?$`)
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
	skipCleanup := false

	// For AEA-encrypted DMGs, check if the decrypted version already exists
	// (e.g. already extracted + mounted by a prior step like mountSystemOsDMGs).
	// Reuse it to avoid overwriting a mounted DMG's backing file.
	if filepath.Ext(dmgPath) == ".aea" {
		decryptedPath := strings.TrimSuffix(dmgPath, filepath.Ext(dmgPath))
		if _, err := os.Stat(decryptedPath); err == nil {
			dmgPath = decryptedPath
			skipCleanup = true
		}
	}

	if !skipCleanup {
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

	// Run handlers with a re-walk per handler (avoids huge in-memory file list)
	for i, handler := range handlers {
		if err := walkFilesInMount(mountPoint, func(file string) error {
			return handler(mountPoint, file)
		}); err != nil {
			return fmt.Errorf("failed to walk files in dir %s: %w", mountPoint, err)
		}
		if betweenHandlers != nil {
			betweenHandlers(i)
		}
	}

	return nil
}

// scanDmg mounts a DMG and runs a single handler across files.
// Why: simple case; multi-pass should use ScanDmgWithMultipleHandlers.
func scanDmg(ipswPath, dmgPath, dmgType, pemDB string, handler func(string, string) error) error {
	skipCleanup := false

	// For AEA-encrypted DMGs, check if the decrypted version already exists
	// (e.g. already extracted + mounted by a prior step like mountSystemOsDMGs).
	// Reuse it to avoid overwriting a mounted DMG's backing file.
	if filepath.Ext(dmgPath) == ".aea" {
		decryptedPath := strings.TrimSuffix(dmgPath, filepath.Ext(dmgPath))
		if _, err := os.Stat(decryptedPath); err == nil {
			dmgPath = decryptedPath
			skipCleanup = true
		}
	}

	if !skipCleanup {
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

	// Stream file paths directly to handler to avoid huge in-memory file list
	if err := walkFilesInMount(mountPoint, func(path string) error {
		return handler(mountPoint, path)
	}); err != nil {
		return fmt.Errorf("failed to walk files in dir %s: %w", mountPoint, err)
	}

	return nil
}

// WalkFilesInRoot streams every regular file under root to handle. Symlinked
// files are skipped; symlinked directories are followed and deduped by resolved
// path. Absolute symlink targets are resolved inside root, never against the
// host filesystem.
func WalkFilesInRoot(root string, handle func(path string) error) error {
	return WalkFilesInRootFrom(root, root, handle)
}

// WalkFilesInRootFrom is like WalkFilesInRoot, but starts walking at start while
// still resolving absolute symlinks relative to root.
func WalkFilesInRootFrom(root, start string, handle func(path string) error) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	startAbs, err := filepath.Abs(start)
	if err != nil {
		return err
	}
	if !pathInRoot(rootAbs, startAbs) {
		return fmt.Errorf("walk start %s escapes root %s", startAbs, rootAbs)
	}

	visitedFiles := make(map[string]bool)
	visitedDirs := make(map[string]bool)

	visitFile := func(path string, info os.FileInfo) error {
		if info == nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		visitKey := absOrSelf(path)
		if !pathInRoot(rootAbs, visitKey) {
			return nil
		}
		if visitedFiles[visitKey] {
			return nil
		}
		visitedFiles[visitKey] = true
		return handle(path)
	}

	var walkDir func(string) error
	walkDir = func(dir string) error {
		return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsPermission(err) {
					log.Debugf("skipping path due to permission denied: %s", path)
					return nil
				}
				log.Debugf("failed to walk root %s from %s: %v", root, dir, err)
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				linkPath, err := resolveSymlinkInRoot(root, path)
				if err != nil {
					return nil
				}
				info, err := os.Stat(linkPath)
				if err != nil {
					return nil
				}
				if info.IsDir() {
					linkKey := absOrSelf(linkPath)
					if visitedDirs[linkKey] {
						return nil
					}
					return walkDir(linkPath)
				}
				return nil
			}

			if info.IsDir() {
				dirKey := absOrSelf(path)
				if visitedDirs[dirKey] {
					return filepath.SkipDir
				}
				visitedDirs[dirKey] = true
				return nil
			}
			return visitFile(path, info)
		})
	}
	return walkDir(start)
}

func absOrSelf(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// FirmwareMemberKey scopes a firmware Mach-O key by its containing IM4P member
// so duplicate payload names from different firmware bundles do not collide.
func FirmwareMemberKey(member, name string) string {
	if name == "" {
		return filepath.ToSlash(filepath.Clean(member))
	}
	return filepath.ToSlash(filepath.Join(member, name))
}

// walkFilesInMount is the shared mounted-root walker behind scanDmg,
// scanDmgMulti, and the ForEach*InMount helpers.
func walkFilesInMount(mountPoint string, handle func(path string) error) error {
	return WalkFilesInRoot(mountPoint, handle)
}

func resolveSymlinkInRoot(root, path string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	current := path
	for range 32 {
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			if !pathInRoot(rootAbs, current) {
				return "", fmt.Errorf("symlink target %s escapes root %s", current, rootAbs)
			}
			return current, nil
		}
		target, err := os.Readlink(current)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			current = filepath.Join(rootAbs, strings.TrimPrefix(filepath.Clean(target), string(filepath.Separator)))
		} else {
			current = filepath.Join(filepath.Dir(current), target)
		}
		current = filepath.Clean(current)
		if !pathInRoot(rootAbs, current) {
			return "", fmt.Errorf("symlink target %s escapes root %s", current, rootAbs)
		}
	}
	return "", fmt.Errorf("symlink chain too deep at %s", path)
}

func pathInRoot(root, path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, absPath)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// handleMachoInMount opens machoPath as a Mach-O (last arch of a FAT), trims the
// mount-point prefix off the key, and calls handler. Shared by the *InIPSW and
// *InMount macho walkers so they produce identical keys.
func handleMachoInMount(mountPoint, machoPath string, handler func(string, *macho.File) error) error {
	if ok, _ := magic.IsMachO(machoPath); !ok {
		return nil
	}
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
	return nil
}

// handlePlistInMount reads a .plist under directory, keyed relative to directory.
// Shared by ForEachPlistInIPSW and ForEachPlistInMount.
func handlePlistInMount(mountPoint, directory, plistPath string, handler func(string, string) error) error {
	if directory != "" && !strings.Contains(plistPath, directory) {
		return nil
	}
	if !strings.HasSuffix(plistPath, ".plist") {
		return nil
	}
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return fmt.Errorf("failed to read plist %s: %v", plistPath, err)
	}
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
	return nil
}

// handleFileInMount emits (dmg, mount-relative path) for a file under directory.
// Shared by ForEachFileInIPSW and ForEachFileInMount.
func handleFileInMount(mountPoint, directory, dmg, filePath string, handler func(string, string) error) error {
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

// ForEachMachoInMount walks an already-mounted root and calls handler for each
// Mach-O. The IPSW-key-preserving twin of the per-volume ForEachMachoInIPSW pass.
func ForEachMachoInMount(mountPoint string, handler func(string, *macho.File) error) error {
	return walkFilesInMount(mountPoint, func(path string) error {
		return handleMachoInMount(mountPoint, path, handler)
	})
}

// ForEachPlistInMount walks an already-mounted root for .plists under directory.
func ForEachPlistInMount(mountPoint, directory string, handler func(string, string) error) error {
	return walkFilesInMount(mountPoint, func(path string) error {
		return handlePlistInMount(mountPoint, directory, path, handler)
	})
}

// ForEachFileInMount walks an already-mounted root, emitting (dmgLabel, path).
func ForEachFileInMount(mountPoint, dmgLabel, directory string, handler func(string, string) error) error {
	return walkFilesInMount(mountPoint, func(path string) error {
		return handleFileInMount(mountPoint, directory, dmgLabel, path, handler)
	})
}

// ForEachFileInZip walks the IPSW zip itself (not its mounted DMGs), emitting
// (dmgLabel, f.Name) for each non-directory file that isn't a DMG/cryptex.
// It matches the whole-zip pass in ForEachFileInIPSW.
func ForEachFileInZip(ipswPath, dmgLabel, directory string, handler func(string, string) error) error {
	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to open IPSW: %v", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// skip DMGs/cryptexes (always a different name, e.g. 090-43228-337.dmg.aea)
		if reDmgAeaFile.MatchString(f.Name) {
			continue
		}
		if err := handleFileInMount("", directory, dmgLabel, f.Name, handler); err != nil {
			return err
		}
	}
	return nil
}

// ForEachMachoInIPSW walks the IPSW and calls the handler for each macho file found
func ForEachMachoInIPSW(ipswPath, pemDbPath string, handler func(string, *macho.File) error) error {
	scanMacho := func(mountPoint, machoPath string) error {
		return handleMachoInMount(mountPoint, machoPath, handler)
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
	handleMacho := func(file string) error {
		if ok, _ := magic.IsMachO(file); !ok {
			return nil
		}
		var m *macho.File
		// UNIVERSAL MACHO
		if fat, err := macho.OpenFat(file); err == nil {
			m = fat.Arches[len(fat.Arches)-1].File
			defer fat.Close()
		} else if errors.Is(err, macho.ErrNotFat) {
			var err2 error
			m, err2 = macho.Open(file)
			if err2 != nil {
				return nil
			}
			defer m.Close()
		} else {
			return nil
		}
		return handler(file, m)
	}

	return WalkFilesInRoot(folder, handleMacho)
}

// ForEachIm4pInIPSW walks the IPSW and calls the handler for each im4p
// firmware Mach-O file found. skippedUnsupportedExclave is called for Exclave
// app bundles that parse as a known but unsupported bundle type.
func ForEachIm4pInIPSW(
	ipswPath string,
	handler func(string, *macho.File) error,
	skippedUnsupportedExclave func(string),
) error {
	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_im4p")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory to store im4ps: %v", err)
	}
	defer os.RemoveAll(tmpDIR)

	im4ps, err := extractIM4PsInIPSW(ipswPath, tmpDIR)
	if err != nil {
		return fmt.Errorf("failed to unzip im4p: %v", err)
	}

	for _, im4pFile := range im4ps {
		if reArmFwIm4p.MatchString(im4pFile.path) {
			im4p, err := img4.OpenPayload(im4pFile.path)
			if err != nil {
				return fmt.Errorf("failed to open im4p file %s: %v", im4pFile.name, err)
			}
			im4pData, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get data from im4p file %s: %v", im4pFile.name, err)
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
					name := FirmwareMemberKey(im4pFile.name, "agx_"+filepath.Base(string(entry.Tag[:])))
					if err := handler(name, m); err != nil {
						return fmt.Errorf("failed to handle macho %s: %w", name, err)
					}
				}
			}
			ftab.Close()
		} else if reExclaveBundleIm4p.MatchString(im4pFile.path) {
			im4p, err := img4.OpenPayload(im4pFile.path)
			if err != nil {
				return fmt.Errorf("failed to open im4p file %s: %v", im4pFile.name, err)
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get data from im4p file %s: %v", im4pFile.name, err)
			}
			im4pName := im4pFile.name
			outDir := filepath.Join(tmpDIR, "exclave", filepath.FromSlash(im4pName))
			out, err := fwcmd.ExtractExclaveCores(data, outDir)
			if err != nil {
				if errors.Is(err, fwcmd.ErrUnsupportedExclaveAppBundleType) {
					if skippedUnsupportedExclave != nil {
						skippedUnsupportedExclave(im4pName)
					}
					log.WithError(err).Warnf("skipping unsupported exclave apps FW %s", im4pName)
					continue
				}
				return fmt.Errorf("failed to split exclave apps FW %s: %w", im4pName, err)
			}
			for _, f := range out {
				if m, err := macho.Open(f); err == nil {
					name := FirmwareMemberKey(im4pName, "exclave_"+filepath.Base(f))
					if err := handler(name, m); err != nil {
						return fmt.Errorf("failed to handle macho %s: %w", f, err)
					}
					m.Close()
				}
			}
		} else {
			im4p, err := img4.OpenPayload(im4pFile.path)
			if err != nil {
				return fmt.Errorf("failed to open im4p file %s: %v", im4pFile.name, err)
			}
			data, err := im4p.GetData()
			if err != nil {
				return fmt.Errorf("failed to get data from im4p file %s: %v", im4pFile.name, err)
			}
			if m, err := macho.NewFile(bytes.NewReader(data)); err == nil {
				name := FirmwareMemberKey(im4pFile.name, "")
				if err := handler(name, m); err != nil {
					return fmt.Errorf("failed to handle macho %s: %w", name, err)
				}
				m.Close()
			} else {
				log.Debugf("failed to parse %s data as macho: %v", im4pFile.name, err)
			}
		}
	}

	return nil
}

type im4pExtraction struct {
	name string
	path string
}

func extractIM4PsInIPSW(ipswPath, dest string) ([]im4pExtraction, error) {
	r, err := zip.OpenReader(ipswPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	if err := os.MkdirAll(dest, 0o750); err != nil {
		return nil, err
	}

	var out []im4pExtraction
	for _, f := range r.File {
		if filepath.Ext(f.Name) != ".im4p" || f.FileInfo().IsDir() {
			continue
		}
		name := filepath.ToSlash(filepath.Clean(f.Name))
		path, err := utils.SanitizeArchivePath(dest, filepath.FromSlash(name))
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		if err := extractZipMember(f, path); err != nil {
			return nil, err
		}
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Extracted %s from %s", path, filepath.Base(ipswPath)))
		out = append(out, im4pExtraction{name: name, path: path})
	}
	return out, nil
}

func extractZipMember(f *zip.File, path string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	of, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(of, rc); err != nil {
		_ = of.Close()
		return err
	}
	return of.Close()
}

func ForEachPlistInIPSW(ipswPath, directory, pemDB string, handler func(string, string) error) error {
	i, err := info.Parse(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW: %v", err)
	}

	scanPlist := func(mountPoint, plistPath string) error {
		return handlePlistInMount(mountPoint, directory, plistPath, handler)
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
		return handleFileInMount(mountPoint, directory, dmg, filePath, handler)
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
		if reDmgAeaFile.MatchString(f.Name) {
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
