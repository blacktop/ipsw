package ent

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/chroma/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/fatih/color"
)

var haveChecked []string // TODO: refactor this

type Entitlements map[string]any

type Config struct {
	Markdown bool
	Color    bool
	DiffTool string
}

func GetDatabase(ipswPath, entDBPath string) (map[string]string, error) {
	entDB := make(map[string]string)

	i, err := info.Parse(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPSW: %v", err)
	}

	// create or load entitlement database
	if _, err := os.Stat(entDBPath); os.IsNotExist(err) {
		utils.Indent(log.Info, 2)("Generating entitlement database file...")

		if appOS, err := i.GetAppOsDmg(); err == nil {
			utils.Indent(log.Info, 3)("Scanning AppOS")
			if ents, err := scanEnts(ipswPath, appOS, "AppOS"); err != nil {
				return nil, fmt.Errorf("failed to scan files in AppOS %s: %v", appOS, err)
			} else {
				for k, v := range ents {
					entDB[k] = v
				}
			}
		}
		if systemOS, err := i.GetSystemOsDmg(); err == nil {
			utils.Indent(log.Info, 3)("Scanning SystemOS")
			if ents, err := scanEnts(ipswPath, systemOS, "SystemOS"); err != nil {
				return nil, fmt.Errorf("failed to scan files in SystemOS %s: %v", systemOS, err)
			} else {
				for k, v := range ents {
					entDB[k] = v
				}
			}
		}
		if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
			utils.Indent(log.Info, 3)("Scanning filesystem")
			if ents, err := scanEnts(ipswPath, fsOS, "filesystem"); err != nil {
				return nil, fmt.Errorf("failed to scan files in filesystem %s: %v", fsOS, err)
			} else {
				for k, v := range ents {
					entDB[k] = v
				}
			}
		}

		buff := new(bytes.Buffer)

		e := gob.NewEncoder(buff)

		// Encoding the map
		err := e.Encode(entDB)
		if err != nil {
			return nil, fmt.Errorf("failed to encode entitlement db to binary: %v", err)
		}

		of, err := os.Create(entDBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create file %s: %v", ipswPath+".entDB", err)
		}
		defer of.Close()

		gzw := gzip.NewWriter(of)
		defer gzw.Close()

		if _, err := buff.WriteTo(gzw); err != nil {
			return nil, fmt.Errorf("failed to write entitlement db to gzip file: %v", err)
		}
	} else {
		log.Info("Found ipsw entitlement database file...")

		edbFile, err := os.Open(entDBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open entitlement database file %s; %v", entDBPath, err)
		}
		defer edbFile.Close()

		gzr, err := gzip.NewReader(edbFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer gzr.Close()

		// Decoding the serialized data
		if err := gob.NewDecoder(gzr).Decode(&entDB); err != nil {
			return nil, fmt.Errorf("failed to decode entitlement database; %v", err)
		}
	}

	return entDB, nil
}

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

func scanEnts(ipswPath, dmgPath, dmgType string) (map[string]string, error) {
	if utils.StrSliceHas(haveChecked, dmgPath) {
		return nil, nil // already checked
	}

	// check if filesystem DMG already exists (due to previous mount command)
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
		defer os.Remove(dmgs[0])
	} else {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Found extracted %s", dmgPath))
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting %s %s", dmgType, dmgPath))
	mountPoint, alreadyMounted, err := utils.MountFS(dmgPath)
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

	var files []string
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("failed to walk mount %s: %v", mountPoint, err)
			return nil
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
	}

	entDB := make(map[string]string)

	for _, file := range files {
		if m, err := macho.Open(file); err == nil {
			if m.CodeSignature() != nil && len(m.CodeSignature().Entitlements) > 0 {
				entDB[strings.TrimPrefix(file, mountPoint)] = m.CodeSignature().Entitlements
			} else {
				entDB[strings.TrimPrefix(file, mountPoint)] = ""
			}
		}
	}

	haveChecked = append(haveChecked, dmgPath)

	return entDB, nil
}
