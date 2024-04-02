// Package diff provides a way to diff two ipsws
package diff

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/blacktop/ipsw/internal/utils"
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

type Config struct {
	Title    string
	IpswOld  string
	IpswNew  string
	KDKs     []string
	LaunchD  bool
	Firmware bool
	Filter   []string
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

// Save saves the diff
func (d *Diff) Save() error {
	if err := os.MkdirAll(d.conf.Output, 0755); err != nil {
		return err
	}

	fname := filepath.Join(d.conf.Output, fmt.Sprintf("%s.md", d.Title))
	log.Infof("Creating diff file: %s", fname)
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(d.String())

	return err
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
	oldDSCes, err := dyld.GetDscPathsInMount(d.Old.MountPath, false)
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

	newDSCes, err := dyld.GetDscPathsInMount(d.New.MountPath, false)
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
	})
	return
}

func (d *Diff) parseLaunchdPlists() error {
	oldConfig, err := extract.LaunchdConfig(d.Old.IPSWPath)
	if err != nil {
		return fmt.Errorf("diff: parseLaunchdPlists: failed to get 'Old' launchd config: %v", err)
	}
	newConfig, err := extract.LaunchdConfig(d.New.IPSWPath)
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
	})
	return
}
