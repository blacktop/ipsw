// Package ent contains functions to extract entitlements from an IPSW
package ent

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
	ents "github.com/blacktop/ipsw/internal/codesign/entitlements"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/info"
)

// Entitlements is a map of entitlements
type Entitlements map[string]any

// Config is the configuration for the entitlements command
type Config struct {
	IPSW              string
	Folder            string
	Database          string
	PemDB             string
	Markdown          bool
	Color             bool
	DiffTool          string
	LaunchConstraints bool

	// UI Config
	Version string
	Host    string
	Port    int
}

// GetDatabase returns the entitlement database for the given IPSW
func GetDatabase(conf *Config) (map[string]string, error) {
	entDB := make(map[string]string)

	// create or load entitlement database
	if _, err := os.Stat(conf.Database); os.IsNotExist(err) {
		utils.Indent(log.Info, 2)("Generating entitlement database file...")
		if len(conf.IPSW) > 0 {
			i, err := info.Parse(conf.IPSW)
			if err != nil {
				return nil, fmt.Errorf("failed to parse IPSW: %v", err)
			}

			if appOS, err := i.GetAppOsDmg(); err == nil {
				utils.Indent(log.Info, 3)("Scanning AppOS")
				if ents, err := scanEnts(conf.IPSW, appOS, "AppOS", conf); err != nil {
					return nil, fmt.Errorf("failed to scan files in AppOS %s: %v", appOS, err)
				} else {
					maps.Copy(entDB, ents)
				}
			}
			if systemOS, err := i.GetSystemOsDmg(); err == nil {
				utils.Indent(log.Info, 3)("Scanning SystemOS")
				if ents, err := scanEnts(conf.IPSW, systemOS, "SystemOS", conf); err != nil {
					return nil, fmt.Errorf("failed to scan files in SystemOS %s: %v", systemOS, err)
				} else {
					maps.Copy(entDB, ents)
				}
			}
			if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
				utils.Indent(log.Info, 3)("Scanning FileSystem")
				if ents, err := scanEnts(conf.IPSW, fsOS, "filesystem", conf); err != nil {
					return nil, fmt.Errorf("failed to scan files in FileSystem %s: %v", fsOS, err)
				} else {
					maps.Copy(entDB, ents)
				}
			}
			if excOS, err := i.GetExclaveOSDmg(); err == nil {
				utils.Indent(log.Info, 3)("Scanning ExclaveOS")
				if ents, err := scanEnts(conf.IPSW, excOS, "ExclaveOS", conf); err != nil {
					return nil, fmt.Errorf("failed to scan files in ExclaveOS %s: %v", excOS, err)
				} else {
					maps.Copy(entDB, ents)
				}
			}
		}

		if len(conf.Folder) > 0 {
			var files []string
			if err := filepath.Walk(conf.Folder, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					// Skip paths with permission errors gracefully
					if os.IsPermission(err) {
						log.Debugf("skipping path due to permission denied: %s", path)
						return nil
					}
					log.Debugf("failed to walk mount %s: %v", conf.Folder, err)
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
				if m.CodeSignature() != nil {
					var output strings.Builder
					// Get entitlements (try normal first, fallback to DER)
					if len(m.CodeSignature().Entitlements) > 0 {
						output.WriteString(m.CodeSignature().Entitlements)
					} else if len(m.CodeSignature().EntitlementsDER) > 0 {
						// Fallback to DER entitlements if normal ones are empty
						if decoded, err := ents.DerDecode(m.CodeSignature().EntitlementsDER); err == nil {
							output.WriteString(decoded)
							log.Warnf("using DER entitlements for %s", file)
						}
					}
					// Add launch constraints if requested (for diff, not for database)
					if conf.LaunchConstraints {
						if len(m.CodeSignature().LaunchConstraintsSelf) > 0 {
							lc, err := cstypes.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsSelf)
							if err == nil {
								if output.Len() > 0 {
									output.WriteString("\n")
								}
								output.WriteString("<!-- Launch Constraints (Self) -->\n")
								lcdata, _ := json.MarshalIndent(lc, "", "  ")
								output.WriteString(string(lcdata))
								output.WriteString("\n")
							}
						}
						if len(m.CodeSignature().LaunchConstraintsParent) > 0 {
							lc, err := cstypes.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsParent)
							if err == nil {
								if output.Len() > 0 {
									output.WriteString("\n")
								}
								output.WriteString("<!-- Launch Constraints (Parent) -->\n")
								lcdata, _ := json.MarshalIndent(lc, "", "  ")
								output.WriteString(string(lcdata))
								output.WriteString("\n")
							}
						}
						if len(m.CodeSignature().LaunchConstraintsResponsible) > 0 {
							lc, err := cstypes.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsResponsible)
							if err == nil {
								if output.Len() > 0 {
									output.WriteString("\n")
								}
								output.WriteString("<!-- Launch Constraints (Responsible) -->\n")
								lcdata, _ := json.MarshalIndent(lc, "", "  ")
								output.WriteString(string(lcdata))
								output.WriteString("\n")
							}
						}
					}

					entDB[strings.TrimPrefix(file, conf.Folder)] = output.String()
				} else {
					entDB[strings.TrimPrefix(file, conf.Folder)] = ""
				}
			}
		}

		if len(conf.Database) > 0 {
			buff := new(bytes.Buffer)

			e := gob.NewEncoder(buff)

			// Encoding the map
			err := e.Encode(entDB)
			if err != nil {
				return nil, fmt.Errorf("failed to encode entitlement db to binary: %v", err)
			}

			of, err := os.Create(conf.Database)
			if err != nil {
				return nil, fmt.Errorf("failed to create file %s: %v", conf.Database, err)
			}
			defer of.Close()

			gzw := gzip.NewWriter(of)
			defer gzw.Close()

			if _, err := buff.WriteTo(gzw); err != nil {
				return nil, fmt.Errorf("failed to write entitlement db to gzip file: %v", err)
			}
		}
	} else {
		log.WithField("database", filepath.Base(conf.Database)).Info("Loading Entitlement DB")

		edbFile, err := os.Open(conf.Database)
		if err != nil {
			return nil, fmt.Errorf("failed to open entitlement database file %s; %v", conf.Database, err)
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
				buf.WriteString(colors.Bold().Sprintf("\n%s\n\n", f2))
				buf.WriteString(out + "\n")
			}
		} else {
			found = true
			if conf.Markdown {
				buf.WriteString(fmt.Sprintf("\n### 🆕 %s\n\n> `%s`\n\n", filepath.Base(f2), f2))
			} else {
				buf.WriteString(colors.Bold().Sprintf("\n🆕 %s\n\n", f2))
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

func scanEnts(ipswPath, dmgPath, dmgType string, conf *Config) (map[string]string, error) {
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

	if filepath.Ext(dmgPath) == ".aea" {
		var err error
		dmgPath, err = aea.Decrypt(&aea.DecryptConfig{
			Input:    dmgPath,
			Output:   filepath.Dir(dmgPath),
			PemDB:    conf.PemDB,
			Proxy:    "",    // TODO: make proxy configurable
			Insecure: false, // TODO: make insecure configurable
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
		}
		defer os.Remove(dmgPath)
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("Mounting %s %s", dmgType, dmgPath))
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

	var files []string
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip paths with permission errors gracefully
			if os.IsPermission(err) {
				log.Debugf("skipping path due to permission denied: %s", path)
				return nil
			}
			log.Debugf("failed to walk mount %s: %v", mountPoint, err)
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
		if m.CodeSignature() != nil {
			var output strings.Builder
			// Get entitlements (try normal first, fallback to DER)
			if len(m.CodeSignature().Entitlements) > 0 {
				output.WriteString(m.CodeSignature().Entitlements)
			} else if len(m.CodeSignature().EntitlementsDER) > 0 {
				// Fallback to DER entitlements if normal ones are empty
				if decoded, err := ents.DerDecode(m.CodeSignature().EntitlementsDER); err == nil {
					output.WriteString(decoded)
					log.Warnf("using DER entitlements for %s", file)
				}
			}
			// Add launch constraints if requested (for diff, not for database)
			if conf.LaunchConstraints {
				if len(m.CodeSignature().LaunchConstraintsSelf) > 0 {
					lc, err := cstypes.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsSelf)
					if err == nil {
						if output.Len() > 0 {
							output.WriteString("\n")
						}
						output.WriteString("<!-- Launch Constraints (Self) -->\n")
						lcdata, _ := json.MarshalIndent(lc, "", "  ")
						output.WriteString(string(lcdata))
						output.WriteString("\n")
					}
				}
				if len(m.CodeSignature().LaunchConstraintsParent) > 0 {
					lc, err := cstypes.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsParent)
					if err == nil {
						if output.Len() > 0 {
							output.WriteString("\n")
						}
						output.WriteString("<!-- Launch Constraints (Parent) -->\n")
						lcdata, _ := json.MarshalIndent(lc, "", "  ")
						output.WriteString(string(lcdata))
						output.WriteString("\n")
					}
				}
				if len(m.CodeSignature().LaunchConstraintsResponsible) > 0 {
					lc, err := cstypes.ParseLaunchContraints(m.CodeSignature().LaunchConstraintsResponsible)
					if err == nil {
						if output.Len() > 0 {
							output.WriteString("\n")
						}
						output.WriteString("<!-- Launch Constraints (Responsible) -->\n")
						lcdata, _ := json.MarshalIndent(lc, "", "  ")
						output.WriteString(string(lcdata))
						output.WriteString("\n")
					}
				}
			}

			entDB[strings.TrimPrefix(file, mountPoint)] = output.String()
		} else {
			entDB[strings.TrimPrefix(file, mountPoint)] = ""
		}
	}

	return entDB, nil
}
