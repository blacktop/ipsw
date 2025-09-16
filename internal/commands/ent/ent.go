// Package ent contains functions to extract entitlements from an IPSW
package ent

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
	"github.com/fatih/color"
)

// Entitlements is a map of entitlements
type Entitlements map[string]any

// Config is the configuration for the entitlements command
type Config struct {
	IPSW     string
	Folder   string
	Database string
	PemDB    string
	Markdown bool
	Color    bool
	DiffTool string

	// UI Config
	Version string
	Host    string
	Port    int
}

// GetDatabase returns the entitlement database for the given IPSW
func GetDatabase(conf *Config) (map[string]string, error) {
	entDB := make(map[string]string)

	if conf.Database != "" {
		if _, err := os.Stat(conf.Database); err == nil {
			return loadEntitlementDatabase(conf.Database)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to stat entitlement database file %s: %v", conf.Database, err)
		}
	}

	utils.Indent(log.Info, 2)("Generating entitlement database file...")

	if len(conf.IPSW) > 0 {
		ents, err := collectEntitlementsFromArchive(conf.IPSW, conf.PemDB)
		if err != nil {
			return nil, err
		}
		maps.Copy(entDB, ents)
	}

	if len(conf.Folder) > 0 {
		var files []string
		if err := filepath.Walk(conf.Folder, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Errorf("failed to walk mount %s: %v", conf.Folder, err)
				return nil
			}
			if !info.IsDir() {
				files = append(files, path)
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("failed to walk files in dir %s: %v", conf.Folder, err)
		}

		for _, file := range files {
			var m *macho.File
			fat, err := macho.OpenFat(file)
			if err == nil {
				m = fat.Arches[len(fat.Arches)-1].File // grab last arch (probably arm64e)
			} else {
				if err == macho.ErrNotFat {
					m, err = macho.Open(file)
					if err != nil {
						log.WithError(err).Warnf("failed to get entitlements for %s", file)
						continue // bad macho file (skip)
					}
				} else {
					continue // not a macho file (skip)
				}
			}
			if m.CodeSignature() != nil && len(m.CodeSignature().Entitlements) > 0 {
				entDB[strings.TrimPrefix(file, conf.Folder)] = m.CodeSignature().Entitlements
			} else {
				entDB[strings.TrimPrefix(file, conf.Folder)] = ""
			}
		}
	}

	if len(conf.Database) > 0 {
		if err := saveEntitlementDatabase(conf.Database, entDB); err != nil {
			return nil, err
		}
	}

	return entDB, nil
}

func loadEntitlementDatabase(path string) (map[string]string, error) {
	entDB := make(map[string]string)

	log.WithField("database", filepath.Base(path)).Info("Loading Entitlement DB")

	edbFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open entitlement database file %s; %v", path, err)
	}
	defer edbFile.Close()

	gzr, err := gzip.NewReader(edbFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	if err := gob.NewDecoder(gzr).Decode(&entDB); err != nil {
		return nil, fmt.Errorf("failed to decode entitlement database; %v", err)
	}

	return entDB, nil
}

func saveEntitlementDatabase(path string, entDB map[string]string) error {
	buff := new(bytes.Buffer)

	if err := gob.NewEncoder(buff).Encode(entDB); err != nil {
		return fmt.Errorf("failed to encode entitlement db to binary: %v", err)
	}

	of, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", path, err)
	}
	defer of.Close()

	gzw := gzip.NewWriter(of)
	defer gzw.Close()

	if _, err := buff.WriteTo(gzw); err != nil {
		return fmt.Errorf("failed to write entitlement db to gzip file: %v", err)
	}

	return nil
}

func collectEntitlementsFromArchive(path, pemDb string) (map[string]string, error) {
	infoData, parseErr := info.Parse(path)
	if parseErr == nil && infoData != nil && infoData.Plists != nil && infoData.Plists.Type != "OTA" {
		return collectEntitlementsFromIPSW(path, infoData, pemDb)
	}

	aa, otaErr := ota.Open(path)
	if otaErr != nil {
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse IPSW: %v; failed to open OTA: %w", parseErr, otaErr)
		}
		return nil, fmt.Errorf("failed to open OTA: %w", otaErr)
	}
	defer aa.Close()

	if _, err := aa.Info(); err != nil {
		return nil, fmt.Errorf("failed to parse OTA metadata: %w", err)
	}

	return collectEntitlementsFromOTA(aa, pemDb)
}

func collectEntitlementsFromIPSW(ipswPath string, i *info.Info, pemDb string) (map[string]string, error) {
	entDB := make(map[string]string)

	if appOS, err := i.GetAppOsDmg(); err == nil {
		utils.Indent(log.Info, 3)("Scanning AppOS")
		ents, err := scanEnts(ipswPath, appOS, "AppOS", pemDb)
		if err != nil {
			return nil, fmt.Errorf("failed to scan files in AppOS %s: %v", appOS, err)
		}
		maps.Copy(entDB, ents)
	}
	if systemOS, err := i.GetSystemOsDmg(); err == nil {
		utils.Indent(log.Info, 3)("Scanning SystemOS")
		ents, err := scanEnts(ipswPath, systemOS, "SystemOS", pemDb)
		if err != nil {
			return nil, fmt.Errorf("failed to scan files in SystemOS %s: %v", systemOS, err)
		}
		maps.Copy(entDB, ents)
	}
	if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
		utils.Indent(log.Info, 3)("Scanning FileSystem")
		ents, err := scanEnts(ipswPath, fsOS, "filesystem", pemDb)
		if err != nil {
			return nil, fmt.Errorf("failed to scan files in FileSystem %s: %v", fsOS, err)
		}
		maps.Copy(entDB, ents)
	}
	if excOS, err := i.GetExclaveOSDmg(); err == nil {
		utils.Indent(log.Info, 3)("Scanning ExclaveOS")
		ents, err := scanEnts(ipswPath, excOS, "ExclaveOS", pemDb)
		if err != nil {
			return nil, fmt.Errorf("failed to scan files in ExclaveOS %s: %v", excOS, err)
		}
		maps.Copy(entDB, ents)
	}

	return entDB, nil
}

func collectEntitlementsFromOTA(aa *ota.AA, pemDb string) (map[string]string, error) {
	entDB := make(map[string]string)

	tmpDir, err := os.MkdirTemp("", "ipsw-ota-ents")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory for OTA entitlements: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cryptexes := []struct {
		name     string
		label    string
		required bool
	}{
		{"system", "OTA System Cryptex", true},
		{"app", "OTA App Cryptex", false},
	}

	for _, cx := range cryptexes {
		dmgPath, err := aa.ExtractCryptex(cx.name, tmpDir)
		if err != nil {
			if cx.required {
				return nil, fmt.Errorf("failed to extract %s: %w", cx.label, err)
			}
			log.WithError(err).Debugf("skipping %s", cx.label)
			continue
		}
		ents, err := scanEntsFromDMG(dmgPath, cx.label, pemDb)
		if err != nil {
			if cx.required {
				return nil, fmt.Errorf("failed to scan %s entitlements: %w", cx.label, err)
			}
			log.WithError(err).Warnf("failed to scan %s entitlements", cx.label)
			continue
		}
		maps.Copy(entDB, ents)
	}

	payloadEnts, err := collectEntitlementsFromPayload(aa)
	if err != nil {
		return nil, err
	}
	maps.Copy(entDB, payloadEnts)

	// NOTE: this found nothing when ran on iOS 26 IPSW vs. OTA
	// looseEnts, err := collectEntitlementsFromLooseFiles(aa)
	// if err != nil {
	// 	return nil, err
	// }
	// maps.Copy(entDB, looseEnts)

	if len(entDB) == 0 {
		return nil, fmt.Errorf("no entitlements extracted from OTA payload")
	}

	return entDB, nil
}

func collectEntitlementsFromPayload(aa *ota.AA) (map[string]string, error) {
	entDB := make(map[string]string)

	pre := regexp.MustCompile(`^payload.\d+$`)
	files := aa.Files()
	if len(files) == 0 {
		return entDB, nil
	}

	tmpDir, err := os.MkdirTemp("", "ipsw-ota-payload")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory for OTA payload extraction: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, file := range files {
		if file == nil || file.IsDir() {
			continue
		}
		if !pre.MatchString(file.Base()) {
			continue
		}

		rc, err := aa.Open(file.Name(), false)
		if err != nil {
			return nil, fmt.Errorf("failed to open OTA payload %s: %w", file.Name(), err)
		}
		var payloadBuf bytes.Buffer
		if err := pbzx.Extract(context.Background(), rc, &payloadBuf, runtime.NumCPU()); err != nil {
			rc.Close()
			return nil, fmt.Errorf("failed to extract OTA payload %s: %w", file.Name(), err)
		}
		rc.Close()

		y := &yaa.YAA{}
		if err := y.Parse(bytes.NewReader(payloadBuf.Bytes())); err != nil {
			return nil, fmt.Errorf("failed to parse OTA payload %s: %w", file.Name(), err)
		}

		payloadRoot := filepath.Join(tmpDir, file.Base())
		if err := extractYAAEntries(y, payloadRoot); err != nil {
			return nil, fmt.Errorf("failed to extract OTA payload %s: %w", file.Name(), err)
		}

		payloadEnts, err := scanEntsFromFolder(payloadRoot, "OTA payload")
		if err != nil {
			return nil, fmt.Errorf("failed to scan OTA payload %s: %w", file.Name(), err)
		}
		maps.Copy(entDB, payloadEnts)
	}

	return entDB, nil
}

func scanEntsFromDMG(dmgPath, dmgLabel, pemDbPath string) (map[string]string, error) {
	originalPath := dmgPath
	if filepath.Ext(dmgPath) == ".aea" {
		var err error
		dmgPath, err = aea.Decrypt(&aea.DecryptConfig{
			Input:    dmgPath,
			Output:   filepath.Dir(dmgPath),
			PemDB:    pemDbPath,
			Insecure: false, // TODO: make insecure configurable
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse AEA encrypted DMG %s: %v", originalPath, err)
		}
		defer os.Remove(dmgPath)
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting %s %s", dmgLabel, dmgPath))
	mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to mount DMG: %v", err)
	}
	if alreadyMounted {
		utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, true)
			}); err != nil {
				utils.Indent(log.Error, 3)(fmt.Sprintf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err))
			}
		}()
	}

	entDB := make(map[string]string)
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("failed to walk mount %s: %v", mountPoint, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		var m *macho.File
		fat, ferr := macho.OpenFat(path)
		if ferr == nil {
			m = fat.Arches[len(fat.Arches)-1].File // grab last arch (probably arm64e)
		} else {
			if ferr == macho.ErrNotFat {
				m, ferr = macho.Open(path)
				if ferr != nil {
					log.WithError(ferr).Warnf("failed to get entitlements for %s", path)
					return nil
				}
			} else {
				return nil // not a macho file (skip)
			}
		}
		relPath := strings.TrimPrefix(path, mountPoint)
		if m.CodeSignature() != nil && len(m.CodeSignature().Entitlements) > 0 {
			entDB[relPath] = m.CodeSignature().Entitlements
		} else {
			entDB[relPath] = ""
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
	}

	return entDB, nil
}

func collectEntitlementsFromLooseFiles(aa *ota.AA) (map[string]string, error) {
	entDB := make(map[string]string)

	files := aa.Files()
	if len(files) == 0 {
		return entDB, nil
	}

	payloadRE := regexp.MustCompile(`^payload.\d+$`)
	cryptexRE := regexp.MustCompile(`^cryptex-`)
	for _, file := range files {
		if file == nil || file.IsDir() {
			continue
		}
		base := file.Base()
		if payloadRE.MatchString(base) {
			continue
		}
		if cryptexRE.MatchString(base) {
			continue
		}
		if strings.Contains(file.Name(), "payloadv2/") {
			continue
		}

		rc, err := aa.Open(file.Name(), true)
		if err != nil {
			return nil, fmt.Errorf("failed to open OTA file %s: %w", file.Name(), err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read OTA file %s: %w", file.Name(), err)
		}

		ent, ok, err := entitlementsFromData(data)
		if err != nil {
			log.WithError(err).Warnf("failed to parse entitlements for OTA file %s", file.Name())
			continue
		}
		if !ok {
			continue
		}

		rel := sanitizeLoosePath(file.Name())
		if _, exists := entDB[rel]; !exists {
			entDB[rel] = ent
		}
	}

	return entDB, nil
}

func scanEntsFromFolder(root, label string) (map[string]string, error) {
	entDB := make(map[string]string)

	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Errorf("failed to walk %s %s: %v", label, path, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		ent, ok, err := readEntitlements(path)
		if err != nil {
			log.WithError(err).Warnf("failed to read entitlements from %s", path)
			return nil
		}
		if !ok {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = d.Name()
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "/") {
			rel = "/" + rel
		}

		entDB[rel] = ent
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to scan %s folder: %w", label, err)
	}

	return entDB, nil
}

func readEntitlements(path string) (string, bool, error) {
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		for _, arch := range fat.Arches {
			if arch.File == nil {
				continue
			}
			if cs := arch.File.CodeSignature(); cs != nil {
				return cs.Entitlements, true, nil
			}
		}
		return "", true, nil
	}

	m, err := macho.Open(path)
	if err != nil {
		return "", false, nil
	}
	defer m.Close()

	if cs := m.CodeSignature(); cs != nil {
		return cs.Entitlements, true, nil
	}
	return "", true, nil
}

func entitlementsFromData(data []byte) (string, bool, error) {
	if len(data) < 4 {
		return "", false, nil
	}

	if fat, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		defer fat.Close()
		for _, arch := range fat.Arches {
			if arch.File == nil {
				continue
			}
			if cs := arch.File.CodeSignature(); cs != nil {
				return cs.Entitlements, true, nil
			}
		}
		return "", true, nil
	}

	m, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", false, nil
	}
	defer m.Close()
	if cs := m.CodeSignature(); cs != nil {
		return cs.Entitlements, true, nil
	}
	return "", true, nil
}

func sanitizeLoosePath(name string) string {
	clean := filepath.Clean(name)
	clean = filepath.ToSlash(clean)
	for strings.HasPrefix(clean, "./") {
		clean = strings.TrimPrefix(clean, "./")
	}
	clean = strings.TrimPrefix(clean, "AssetData/")
	for strings.HasPrefix(clean, "/") {
		clean = strings.TrimPrefix(clean, "/")
	}
	if clean == "" {
		return "/" + filepath.ToSlash(filepath.Base(name))
	}
	return "/" + clean
}

func extractYAAEntries(archive *yaa.YAA, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("failed to create OTA payload root %s: %w", dest, err)
	}

	for _, entry := range archive.Entries {
		cleanName := filepath.Clean(entry.Path)
		if cleanName == "." || cleanName == "" {
			continue
		}
		dstPath := filepath.Join(dest, cleanName)
		rel, err := filepath.Rel(dest, dstPath)
		if err != nil {
			return fmt.Errorf("failed to compute relative OTA payload path for %s: %w", entry.Path, err)
		}
		if strings.HasPrefix(rel, "..") {
			return fmt.Errorf("invalid OTA payload path traversal detected: %s", entry.Path)
		}
		switch entry.Type {
		case yaa.Directory:
			if err := os.MkdirAll(dstPath, 0o755); err != nil {
				return fmt.Errorf("failed to create OTA payload directory %s: %w", dstPath, err)
			}
		case yaa.RegularFile:
			if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
				return fmt.Errorf("failed to prepare OTA payload directory %s: %w", filepath.Dir(dstPath), err)
			}
			data := make([]byte, entry.Size)
			if _, err := entry.Read(data); err != nil {
				return fmt.Errorf("failed to read OTA payload entry %s: %w", entry.Path, err)
			}
			if err := os.WriteFile(dstPath, data, 0o644); err != nil {
				return fmt.Errorf("failed to write OTA payload entry %s: %w", entry.Path, err)
			}
		case yaa.SymbolicLink:
			if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
				return fmt.Errorf("failed to prepare OTA payload symlink dir %s: %w", filepath.Dir(dstPath), err)
			}
			if err := os.Symlink(entry.Link, dstPath); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("failed to create OTA payload symlink %s: %w", entry.Path, err)
			}
		default:
			continue
		}
	}

	return nil
}

// DiffDatabases compares two entitlement databases and returns a diff
func DiffDatabases(db1, db2 map[string]string, conf *Config) (string, error) {
	var err error
	var dat bytes.Buffer
	buf := bufio.NewWriter(&dat)

	// sort latest entitlements DB's files
	var files []string
	for f := range db2 {
		files = append(files, f)
	}

	sort.Strings(files)

	found := false
	for _, f2 := range files { // DIFF ALL ENTITLEMENTS
		e2 := db2[f2]
		if e1, ok := db1[f2]; ok {
			var out string
			if conf.Markdown {
				out, err = utils.GitDiff(e1+"\n", e2+"\n", &utils.GitDiffConfig{Color: false, Tool: "git"})
				if err != nil {
					return "", err
				}
			} else {
				out, err = utils.GitDiff(e1+"\n", e2+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
				if err != nil {
					return "", err
				}
			}
			if len(out) == 0 {
				continue
			}
			found = true
			if conf.Markdown {
				buf.WriteString(fmt.Sprintf("### %s\n\n> `%s`\n\n", filepath.Base(f2), f2))
				buf.WriteString("```diff\n" + out + "\n```\n")
			} else {
				buf.WriteString(color.New(color.Bold).Sprintf("\n%s\n\n", f2))
				buf.WriteString(out + "\n")
			}
		} else {
			found = true
			if conf.Markdown {
				buf.WriteString(fmt.Sprintf("\n### 🆕 %s\n\n> `%s`\n\n", filepath.Base(f2), f2))
			} else {
				buf.WriteString(color.New(color.Bold).Sprintf("\n🆕 %s\n\n", f2))
			}
			if len(e2) == 0 {
				buf.WriteString("- No entitlements *(yet)*\n")
			} else {
				if conf.Color {
					if err := quick.Highlight(buf, e2, "xml", "terminal256", "nord"); err != nil {
						return "", err
					}
				} else {
					if conf.Markdown {
						buf.WriteString("```xml\n" + e2 + "\n```\n")
					} else {
						buf.WriteString(e2 + "\n")
					}
				}
			}
		}
	}

	if !found {
		buf.WriteString("- No differences found\n")
	}

	buf.Flush()

	return dat.String(), nil
}

func scanEnts(ipswPath, dmgPath, dmgType, pemDbPath string) (map[string]string, error) {
	localPath := dmgPath
	if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
		dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
			return strings.EqualFold(filepath.Base(f.Name), dmgPath)
		})
		if err != nil {
			return nil, fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
		}
		if len(dmgs) == 0 {
			return nil, fmt.Errorf("failed to find %s in IPSW", dmgPath)
		}
		localPath = dmgs[0]
		defer os.Remove(localPath)
	} else {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Found extracted %s", dmgPath))
	}

	return scanEntsFromDMG(localPath, dmgType, pemDbPath)
}
