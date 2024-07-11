// Package diff provides a way to diff two ipsws
package diff

import (
	"archive/zip"
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	dcmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/commands/dwarf"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/commands/extract"
	kcmd "github.com/blacktop/ipsw/internal/commands/kernel"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

type kernel struct {
	Path    string
	Version *kernelcache.Version
	Kexts   []string
}

type mount struct {
	DmgPath   string
	MountPath string
	IsMounted bool
}

type PlistDiff struct {
	New     []string          `json:"new,omitempty"`
	Removed []string          `json:"removed,omitempty"`
	Updated map[string]string `json:"changed,omitempty"`
}

type Config struct {
	Title    string
	IpswOld  string
	IpswNew  string
	KDKs     []string
	LaunchD  bool
	Firmware bool
	Features bool
	CStrings bool
	Filter   []string
	PemDB    string
	Output   string
}

// Context is the context for the diff
type Context struct {
	IPSWPath        string
	Info            *info.Info
	Version         string
	Build           string
	Folder          string
	Mount           map[string]mount
	SystemOsDmgPath string
	MountPath       string
	IsMounted       bool
	Kernel          kernel
	DSC             string
	Webkit          string
	KDK             string
	PemDB           string

	mu *sync.Mutex
}

// Diff is the diff
type Diff struct {
	Title string `json:"title,omitempty"`

	Old Context `json:"-"`
	New Context `json:"-"`

	Kexts     *mcmd.MachoDiff `json:"kexts,omitempty"`
	KDKs      string          `json:"kdks,omitempty"`
	Ents      string          `json:"ents,omitempty"`
	Dylibs    *mcmd.MachoDiff `json:"dylibs,omitempty"`
	Machos    *mcmd.MachoDiff `json:"machos,omitempty"`
	Firmwares *mcmd.MachoDiff `json:"firmwares,omitempty"`
	Launchd   string          `json:"launchd,omitempty"`
	Features  *PlistDiff      `json:"features,omitempty"`

	tmpDir string `json:"-"`
	conf   *Config
}

// New news the diff
func New(conf *Config) *Diff {
	if len(conf.KDKs) == 0 {
		return &Diff{
			Title: conf.Title,
			Old: Context{
				IPSWPath: conf.IpswOld,
				Mount:    make(map[string]mount),
			},
			New: Context{
				IPSWPath: conf.IpswNew,
				Mount:    make(map[string]mount),
			},
			conf: conf,
		}
	}
	return &Diff{
		Title: conf.Title,
		Old: Context{
			IPSWPath: conf.IpswOld,
			Mount:    make(map[string]mount),
			KDK:      conf.KDKs[0],
		},
		New: Context{
			IPSWPath: conf.IpswNew,
			Mount:    make(map[string]mount),
			KDK:      conf.KDKs[1],
		},
		conf: conf,
	}
}

func (d *Diff) SetOutput(output string) {
	if d.conf == nil {
		d.conf = &Config{Output: output}
	} else {
		d.conf.Output = output
	}
}

func (d *Diff) TitleToFilename() string {
	out := strings.ReplaceAll(d.Title, " ", "_")
	out = strings.ReplaceAll(out, ".", "_")
	out = strings.ReplaceAll(out, "(", "")
	return strings.ReplaceAll(out, ")", "")
}

// Save saves the diff
func (d *Diff) Save() error {
	if err := os.MkdirAll(d.conf.Output, 0755); err != nil {
		return err
	}

	idiff, err := os.Create(filepath.Join(d.conf.Output, d.TitleToFilename()+".idiff"))
	if err != nil {
		return err
	}
	defer idiff.Close()

	d.Old.Info = nil
	d.New.Info = nil

	gob.Register([]any{})
	gob.Register(map[string]any{})

	buff := new(bytes.Buffer)
	if err := gob.NewEncoder(buff).Encode(&d); err != nil {
		return fmt.Errorf("failed to encode diff: %v", err)
	}

	log.Infof("Saving pickled IPSW diff: %s", idiff.Name())
	if _, err = buff.WriteTo(idiff); err != nil {
		return fmt.Errorf("failed to write diff to file: %v", err)
	}

	return nil
}

func (d *Diff) getInfo() (err error) {
	d.Old.Info, err = info.Parse(d.Old.IPSWPath)
	if err != nil {
		return fmt.Errorf("failed to parse 'Old' IPSW: %v", err)
	}
	d.New.Info, err = info.Parse(d.New.IPSWPath)
	if err != nil {
		return fmt.Errorf("failed to parse 'New' IPSW: %v", err)
	}

	d.Old.Version = d.Old.Info.Plists.BuildManifest.ProductVersion
	d.Old.Build = d.Old.Info.Plists.BuildManifest.ProductBuildVersion
	d.Old.Folder, err = d.Old.Info.GetFolder()
	if err != nil {
		log.Errorf("failed to get folder from 'Old' IPSW metadata: %v", err)
	}
	d.Old.Folder = filepath.Join(d.tmpDir, d.Old.Folder)

	d.New.Version = d.New.Info.Plists.BuildManifest.ProductVersion
	d.New.Build = d.New.Info.Plists.BuildManifest.ProductBuildVersion
	d.New.Folder, err = d.New.Info.GetFolder()
	if err != nil {
		log.Errorf("failed to get folder from 'New' IPSW metadata: %v", err)
	}
	d.New.Folder = filepath.Join(d.tmpDir, d.New.Folder)

	if d.Title == "" {
		d.Title = fmt.Sprintf("%s (%s) .vs %s (%s)", d.Old.Version, d.Old.Build, d.New.Version, d.New.Build)
	}

	return nil
}

// Diff diffs the diff
func (d *Diff) Diff() (err error) {

	d.tmpDir, err = os.MkdirTemp(os.TempDir(), "ipsw-diff")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(d.tmpDir)

	if err := d.getInfo(); err != nil {
		return err
	}

	log.Info("Diffing KERNELCACHES")
	if err := d.parseKernelcache(); err != nil {
		return err
	}

	if d.Old.KDK != "" && d.New.KDK != "" {
		log.Info("Diffing KDKS")
		if err := d.parseKDKs(); err != nil {
			return err
		}
	}

	log.Info("Diffing DYLD_SHARED_CACHES")
	if err := d.mountSystemOsDMGs(); err != nil {
		return fmt.Errorf("failed to mount DMGs: %v", err)
	}
	defer d.unmountSystemOsDMGs()

	if err := d.parseDSC(); err != nil {
		return err
	}

	log.Info("Diffing MachOs")
	if err := d.parseMachos(); err != nil {
		return fmt.Errorf("failed to parse MachOs: %v", err)
	}

	if d.conf.LaunchD {
		log.Info("Diffing launchd PLIST")
		if err := d.parseLaunchdPlists(); err != nil {
			return fmt.Errorf("failed to parse launchd config plists: %v", err)
		}
	}

	if d.conf.Firmware {
		log.Info("Diffing Firmware")
		if err := d.parseFirmwares(); err != nil {
			return err
		}
	}

	if d.conf.Features {
		log.Info("Diffing Feature Flags")
		if err := d.parseFeatureFlags(); err != nil {
			return err
		}
	}

	log.Info("Diffing ENTITLEMENTS")
	d.Ents, err = d.parseEntitlements()
	if err != nil {
		return err
	}

	return nil
}

func mountDMG(ctx *Context) (err error) {
	ctx.SystemOsDmgPath, err = ctx.Info.GetSystemOsDmg()
	if err != nil {
		if errors.Is(err, info.ErrorCryptexNotFound) {
			utils.Indent(log.Warn, 2)("failed to get SystemOS DMG; trying filesystem DMG")
			ctx.SystemOsDmgPath, err = ctx.Info.GetFileSystemOsDmg()
			if err != nil {
				return fmt.Errorf("failed to get filesystem DMG: %v", err)
			}
		} else {
			return fmt.Errorf("failed to get SystemOS DMG: %v", err)
		}
	}
	if _, err := os.Stat(ctx.SystemOsDmgPath); os.IsNotExist(err) {
		dmgs, err := utils.Unzip(ctx.IPSWPath, "", func(f *zip.File) bool {
			return strings.EqualFold(filepath.Base(f.Name), ctx.SystemOsDmgPath)
		})
		if err != nil {
			return fmt.Errorf("failed to extract %s from IPSW: %v", ctx.SystemOsDmgPath, err)
		}
		if len(dmgs) == 0 {
			return fmt.Errorf("failed to find %s in IPSW", ctx.SystemOsDmgPath)
		}
	} else {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Found extracted %s", ctx.SystemOsDmgPath))
	}
	if filepath.Ext(ctx.SystemOsDmgPath) == ".aea" {
		ctx.SystemOsDmgPath, err = aea.Decrypt(ctx.SystemOsDmgPath, filepath.Dir(ctx.SystemOsDmgPath), nil, ctx.PemDB)
		if err != nil {
			return fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
		}
	}
	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", ctx.SystemOsDmgPath))
	ctx.MountPath, ctx.IsMounted, err = utils.MountDMG(ctx.SystemOsDmgPath)
	if err != nil {
		if !errors.Is(err, utils.ErrMountResourceBusy) {
			return fmt.Errorf("failed to mount DMG: %v", err)
		}
	}
	if ctx.IsMounted {
		utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", ctx.SystemOsDmgPath))
	}
	return nil
}

func (d *Diff) mountSystemOsDMGs() (err error) {
	log.Info("Mounting 'Old' SystemOS DMG")
	if err := mountDMG(&d.Old); err != nil {
		return err
	}
	log.Info("Mounting 'New' SystemOS DMG")
	if err := mountDMG(&d.New); err != nil {
		return err
	}
	return nil
}

func (d *Diff) unmountSystemOsDMGs() error {
	utils.Indent(log.Info, 2)("Unmounting 'Old' SystemOS DMG")
	if err := utils.Retry(3, 2*time.Second, func() error {
		return utils.Unmount(d.Old.MountPath, false)
	}); err != nil {
		utils.Indent(log.Error, 3)(fmt.Sprintf("failed to unmount 'Old' SystemOS DMG: %v", err))
	}
	utils.Indent(log.Info, 2)("Unmounting 'New' SystemOS DMG")
	if err := utils.Retry(3, 2*time.Second, func() error {
		return utils.Unmount(d.New.MountPath, false)
	}); err != nil {
		utils.Indent(log.Error, 3)(fmt.Sprintf("failed to unmount 'New' SystemOS DMG: %v", err))
	}
	utils.Indent(log.Info, 2)("Deleting 'Old' SystemOS DMG")
	os.Remove(d.Old.SystemOsDmgPath)
	utils.Indent(log.Info, 2)("Deleting 'New' SystemOS DMG")
	os.Remove(d.New.SystemOsDmgPath)
	return nil
}

func (d *Diff) parseKernelcache() error {
	if _, err := kernelcache.Extract(d.Old.IPSWPath, d.Old.Folder, ""); err != nil {
		return fmt.Errorf("failed to extract kernelcaches from 'Old' IPSW: %v", err)
	}
	if _, err := kernelcache.Extract(d.New.IPSWPath, d.New.Folder, ""); err != nil {
		return fmt.Errorf("failed to extract kernelcaches from 'New' IPSW: %v", err)
	}

	for kmodel := range d.Old.Info.Plists.GetKernelCaches() {
		if _, ok := d.Old.Info.Plists.GetKernelCaches()[kmodel]; !ok {
			return fmt.Errorf("failed to find kernelcache for %s in 'Old' IPSW: `ipsw diff` expects you to compare 2 versions of the same IPSW device type", kmodel)
		} else if len(d.Old.Info.Plists.GetKernelCaches()[kmodel]) == 0 {
			return fmt.Errorf("failed to find kernelcache for %s in 'Old' IPSW", kmodel)
		}
		if _, ok := d.New.Info.Plists.GetKernelCaches()[kmodel]; !ok {
			return fmt.Errorf("failed to find kernelcache for %s in 'New' IPSW: `ipsw diff` expects you to compare 2 versions of the same IPSW device type", kmodel)
		} else if len(d.New.Info.Plists.GetKernelCaches()[kmodel]) == 0 {
			return fmt.Errorf("failed to find kernelcache for %s in 'New' IPSW", kmodel)
		}
		kcache1 := d.Old.Info.Plists.GetKernelCaches()[kmodel][0]
		kcache2 := d.New.Info.Plists.GetKernelCaches()[kmodel][0]
		d.Old.Kernel.Path = filepath.Join(d.Old.Folder, d.Old.Info.GetKernelCacheFileName(kcache1))
		d.New.Kernel.Path = filepath.Join(d.New.Folder, d.New.Info.GetKernelCacheFileName(kcache2))
		break // just use first kernelcache for now
	}

	m1, err := macho.Open(d.Old.Kernel.Path)
	if err != nil {
		return fmt.Errorf("failed to open kernelcache: %v", err)
	}
	d.Old.Kernel.Version, err = kernelcache.GetVersion(m1)
	if err != nil {
		return fmt.Errorf("failed to get kernelcache version: %v", err)
	}
	defer m1.Close()

	m2, err := macho.Open(d.New.Kernel.Path)
	if err != nil {
		return fmt.Errorf("failed to open kernelcache: %v", err)
	}
	d.New.Kernel.Version, err = kernelcache.GetVersion(m2)
	if err != nil {
		return fmt.Errorf("failed to get kernelcache version: %v", err)
	}
	defer m2.Close()

	d.Kexts, err = kcmd.Diff(m1, m2, &mcmd.DiffConfig{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
		Filter:   d.conf.Filter,
		CStrings: d.conf.CStrings,
	})
	if err != nil {
		return err
	}

	// // diff kexts
	// d.Old.Kernel.Kexts, err = kernelcache.KextList(d.Old.Kernel.Path, true)
	// if err != nil {
	// 	return err
	// }
	// d.New.Kernel.Kexts, err = kernelcache.KextList(d.New.Kernel.Path, true)
	// if err != nil {
	// 	return err
	// }
	// out, err := utils.GitDiff(
	// 	strings.Join(d.Old.Kernel.Kexts, "\n")+"\n",
	// 	strings.Join(d.New.Kernel.Kexts, "\n")+"\n",
	// 	&utils.GitDiffConfig{Color: false, Tool: "git"})
	// if err != nil {
	// 	return err
	// }
	// if len(out) == 0 {
	// 	d.Kexts = "- No differences found"
	// } else {
	// 	d.Kexts = "```diff\n" + out + "\n```"
	// }

	return nil
}

func (d *Diff) parseKDKs() (err error) {
	if !strings.Contains(d.Old.KDK, ".dSYM/Contents/Resources/DWARF") {
		d.Old.KDK = filepath.Join(d.Old.KDK+".dSYM/Contents/Resources/DWARF", filepath.Base(d.Old.KDK))
	}
	if !strings.Contains(d.New.KDK, ".dSYM/Contents/Resources/DWARF") {
		d.New.KDK = filepath.Join(d.New.KDK+".dSYM/Contents/Resources/DWARF", filepath.Base(d.New.KDK))
	}
	d.KDKs, err = dwarf.DiffStructures(d.Old.KDK, d.New.KDK, &dwarf.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
	d.Old.KDK, _, _ = strings.Cut(strings.TrimPrefix(d.Old.KDK, "/Library/Developer/KDKs/"), ".dSYM/Contents/Resources/DWARF")
	d.New.KDK, _, _ = strings.Cut(strings.TrimPrefix(d.New.KDK, "/Library/Developer/KDKs/"), ".dSYM/Contents/Resources/DWARF")
	return
}

func (d *Diff) parseDSC() error {
	/* OLD DSC */
	oldDSCes, err := dyld.GetDscPathsInMount(d.Old.MountPath, false, false)
	if err != nil {
		return fmt.Errorf("failed to get DSC paths in %s: %v", d.Old.MountPath, err)
	}
	if len(oldDSCes) == 0 {
		return fmt.Errorf("no DSCs found in 'Old' IPSW mount %s", d.Old.MountPath)
	}

	dscOLD, err := dyld.Open(oldDSCes[0])
	if err != nil {
		return fmt.Errorf("failed to open DSC: %v", err)
	}
	defer dscOLD.Close()

	/* NEW DSC */

	newDSCes, err := dyld.GetDscPathsInMount(d.New.MountPath, false, false)
	if err != nil {
		return fmt.Errorf("failed to get DSC paths in %s: %v", d.New.MountPath, err)
	}
	if len(newDSCes) == 0 {
		return fmt.Errorf("no DSCs found in 'New' IPSW mount %s", d.New.MountPath)
	}

	dscNEW, err := dyld.Open(newDSCes[0])
	if err != nil {
		return fmt.Errorf("failed to open DSC: %v", err)
	}
	defer dscNEW.Close()

	/* DIFF WEBKIT*/

	d.Old.Webkit, err = dcmd.GetWebkitVersion(dscOLD)
	if err != nil {
		return fmt.Errorf("failed to get WebKit version: %v", err)
	}

	d.New.Webkit, err = dcmd.GetWebkitVersion(dscNEW)
	if err != nil {
		return fmt.Errorf("failed to get WebKit version: %v", err)
	}

	d.Dylibs, err = dcmd.Diff(dscOLD, dscNEW, &mcmd.DiffConfig{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
		Filter:   d.conf.Filter,
		CStrings: d.conf.CStrings,
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Diff) parseEntitlements() (string, error) {
	oldDB, err := ent.GetDatabase(&ent.Config{IPSW: d.Old.IPSWPath})
	if err != nil {
		return "", err
	}

	newDB, err := ent.GetDatabase(&ent.Config{IPSW: d.New.IPSWPath})
	if err != nil {
		return "", err
	}

	return ent.DiffDatabases(oldDB, newDB, &ent.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
}

func (d *Diff) parseMachos() (err error) {
	d.Machos, err = mcmd.DiffIPSW(d.Old.IPSWPath, d.New.IPSWPath, &mcmd.DiffConfig{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
		Filter:   d.conf.Filter,
		CStrings: d.conf.CStrings,
	})
	return
}

func (d *Diff) parseLaunchdPlists() error {
	oldConfig, err := extract.LaunchdConfig(d.Old.IPSWPath, d.conf.PemDB)
	if err != nil {
		return fmt.Errorf("diff: parseLaunchdPlists: failed to get 'Old' launchd config: %v", err)
	}
	newConfig, err := extract.LaunchdConfig(d.New.IPSWPath, d.conf.PemDB)
	if err != nil {
		return fmt.Errorf("diff: parseLaunchdPlists: failed to get 'New' launchd config: %v", err)
	}
	out, err := utils.GitDiff(
		string(oldConfig)+"\n",
		string(newConfig)+"\n",
		&utils.GitDiffConfig{Color: false, Tool: "git"})
	if err != nil {
		return err
	}
	if len(out) > 0 {
		d.Launchd = "```diff\n" + out + "\n```"
	}

	return nil
}

func (d *Diff) parseFirmwares() (err error) {
	d.Firmwares, err = mcmd.DiffFirmwares(d.Old.IPSWPath, d.New.IPSWPath, &mcmd.DiffConfig{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
		Filter:   d.conf.Filter,
		CStrings: d.conf.CStrings,
	})
	return
}

func (d *Diff) parseFeatureFlags() (err error) {
	d.Features = &PlistDiff{
		Updated: make(map[string]string),
	}
	conf := &mcmd.DiffConfig{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	}

	oldPlists := make(map[string]string)
	if err := search.ForEachPlistInIPSW(d.Old.IPSWPath, "/System/Library/FeatureFlags", d.conf.PemDB, func(path string, content string) error {
		oldPlists[path] = content
		return nil
	}); err != nil {
		return err
	}

	var prevFiles []string
	for f := range oldPlists {
		prevFiles = append(prevFiles, f)
	}
	slices.Sort(prevFiles)

	newPlists := make(map[string]string)
	if err := search.ForEachPlistInIPSW(d.New.IPSWPath, "/System/Library/FeatureFlags", d.conf.PemDB, func(path string, content string) error {
		newPlists[path] = content
		return nil
	}); err != nil {
		return err
	}

	var nextFiles []string
	for f := range newPlists {
		nextFiles = append(nextFiles, f)
	}
	slices.Sort(nextFiles)

	/* DIFF IPSW */
	d.Features.New = utils.Difference(nextFiles, prevFiles)
	d.Features.Removed = utils.Difference(prevFiles, nextFiles)

	for _, f2 := range nextFiles {
		dat2 := newPlists[f2]
		if dat1, ok := oldPlists[f2]; ok {
			if strings.EqualFold(dat2, dat1) {
				continue
			}
			var out string
			if conf.Markdown {
				out, err = utils.GitDiff(dat1+"\n", dat2+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
				if err != nil {
					return err
				}
			} else {
				out, err = utils.GitDiff(dat1+"\n", dat2+"\n", &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
				if err != nil {
					return err
				}
			}
			if len(out) == 0 { // no diff
				continue
			}
			if conf.Markdown {
				d.Features.Updated[f2] = "```diff\n" + out + "\n```\n"
			} else {
				d.Features.Updated[f2] = out
			}
		}
	}

	return nil
}
