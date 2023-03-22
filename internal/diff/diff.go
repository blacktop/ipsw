package diff

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/commands/dwarf"
	"github.com/blacktop/ipsw/internal/commands/ent"
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

type Context struct {
	IPSWPath        string
	Info            *info.Info
	Version         string
	Build           string
	Folder          string
	SystemOsDmgPath string
	MountPath       string
	IsMounted       bool
	Kernel          kernel
	DSC             string
	Webkit          string
	KDK             string
}

type Diff struct {
	Title string

	Old Context
	New Context

	Kexts  string
	KDKs   string
	Ents   string
	Dylibs string

	tmpDir string
}

// New news the diff
func New(title, ipswOld, ipswNew string, kdks []string) *Diff {
	return &Diff{
		Title: title,
		Old: Context{
			IPSWPath: ipswOld,
			KDK:      kdks[0],
		},
		New: Context{
			IPSWPath: ipswNew,
			KDK:      kdks[1],
		},
	}
}

// Save saves the diff
func (d *Diff) Save(folder string) error {
	if err := os.MkdirAll(folder, 0755); err != nil {
		return err
	}

	fname := filepath.Join(folder, fmt.Sprintf("%s.md", d.Title))
	log.Infof("Creating diff file: %s", fname)
	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(d.String())

	return err
}

// Diff diffs the diff
func (d *Diff) Diff() (err error) {

	d.tmpDir, err = os.MkdirTemp(os.TempDir(), "ipsw-diff")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(d.tmpDir)

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
		return fmt.Errorf("failed to get SystemOS DMG: %v", err)
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
	ctx.MountPath, ctx.IsMounted, err = utils.MountFS(ctx.SystemOsDmgPath)
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
	utils.Retry(3, 2*time.Second, func() error {
		return utils.Unmount(d.Old.MountPath, false)
	})
	utils.Indent(log.Info, 2)("Unmounting 'New' SystemOS DMG")
	utils.Retry(3, 2*time.Second, func() error {
		return utils.Unmount(d.New.MountPath, false)
	})
	os.Remove(d.Old.SystemOsDmgPath)
	os.Remove(d.New.SystemOsDmgPath)
	return nil
}

func (d *Diff) parseKernelcache() error {
	if err := kernelcache.Extract(d.Old.IPSWPath, d.Old.Folder); err != nil {
		return fmt.Errorf("failed to extract kernelcaches from 'Old' IPSW: %v", err)
	}
	if err := kernelcache.Extract(d.New.IPSWPath, d.New.Folder); err != nil {
		return fmt.Errorf("failed to extract kernelcaches from 'New' IPSW: %v", err)
	}

	for kmodel := range d.Old.Info.Plists.GetKernelCaches() {
		kcache1 := d.Old.Info.Plists.GetKernelCaches()[kmodel][0]
		kcache2 := d.New.Info.Plists.GetKernelCaches()[kmodel][0]
		d.Old.Kernel.Path = filepath.Join(d.Old.Folder, d.Old.Info.GetKernelCacheFileName(kcache1))
		d.New.Kernel.Path = filepath.Join(d.New.Folder, d.New.Info.GetKernelCacheFileName(kcache2))
		break // just use first kernelcache for now
	}

	m, err := macho.Open(d.Old.Kernel.Path)
	if err != nil {
		return fmt.Errorf("failed to open kernelcache: %v", err)
	}
	d.Old.Kernel.Version, err = kernelcache.GetVersion(m)
	if err != nil {
		return fmt.Errorf("failed to get kernelcache version: %v", err)
	}
	m.Close()

	m, err = macho.Open(d.New.Kernel.Path)
	if err != nil {
		return fmt.Errorf("failed to open kernelcache: %v", err)
	}
	d.New.Kernel.Version, err = kernelcache.GetVersion(m)
	if err != nil {
		return fmt.Errorf("failed to get kernelcache version: %v", err)
	}
	m.Close()

	// diff kexts
	d.Old.Kernel.Kexts, err = kernelcache.KextList(d.Old.Kernel.Path, true)
	if err != nil {
		return err
	}
	d.New.Kernel.Kexts, err = kernelcache.KextList(d.New.Kernel.Path, true)
	if err != nil {
		return err
	}
	out, err := utils.GitDiff(
		strings.Join(d.Old.Kernel.Kexts, "\n")+"\n",
		strings.Join(d.New.Kernel.Kexts, "\n")+"\n",
		&utils.GitDiffConfig{Color: false, Tool: "git"})
	if err != nil {
		return err
	}
	if len(out) == 0 {
		d.Kexts = "- No differences found"
	} else {
		d.Kexts = "```diff\n" + out + "\n```"
	}

	return nil
}

func (d *Diff) parseKDKs() (err error) {
	// foundOld := false
	// foundNew := false
	// if err := filepath.Walk("/Library/Developer/KDKs", func(path string, info fs.FileInfo, err error) error {
	// 	if err != nil {
	// 		return fmt.Errorf("failed to walk KDKs: %v", err)
	// 	}
	// 	if info.IsDir() {
	// 		return nil // skip
	// 	}
	// 	if !strings.Contains(path, "kernel") {
	// 		return nil // skip
	// 	}
	// 	m, err := macho.Open(path)
	// 	if err != nil {
	// 		return nil // skip
	// 	}
	// 	defer m.Close()
	// 	ver, err := kernelcache.GetVersion(m)
	// 	if err != nil {
	// 		return nil // skip
	// 	}

	// 	if ver.Kernel.XNU == d.Old.Kernel.Version.Kernel.XNU { // TODO: these don't match perfectly so we need to find the closest match
	// 		d.Old.KDK = path
	// 		foundOld = true
	// 	}
	// 	if ver.Kernel.XNU == d.New.Kernel.Version.Kernel.XNU {
	// 		d.New.KDK = path
	// 		foundNew = true
	// 	}
	// 	if foundOld && foundNew {
	// 		return filepath.SkipAll
	// 	}

	// 	return nil
	// }); err != nil {
	// 	if !errors.Is(err, filepath.SkipAll) {
	// 		return err
	// 	}
	// }

	// diff sructs
	d.KDKs, err = dwarf.DiffStructures(d.Old.KDK, d.New.KDK, &dwarf.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Diff) parseDSC() error {
	oldDSCes, err := dyld.GetDscPathsInMount(d.Old.MountPath)
	if err != nil {
		return fmt.Errorf("failed to get DSC paths in %s: %v", d.Old.MountPath, err)
	}
	newDSCes, err := dyld.GetDscPathsInMount(d.New.MountPath)
	if err != nil {
		return fmt.Errorf("failed to get DSC paths in %s: %v", d.New.MountPath, err)
	}

	dscOLD, err := dyld.Open(oldDSCes[0])
	if err != nil {
		return fmt.Errorf("failed to open DSC: %v", err)
	}
	defer dscOLD.Close()

	image, err := dscOLD.Image("WebKit")
	if err != nil {
		return fmt.Errorf("image not in %s: %v", oldDSCes[0], err)
	}

	m, err := image.GetPartialMacho()
	if err != nil {
		return err
	}

	d.Old.Webkit = m.SourceVersion().Version.String()

	dylib2verOLD := make(map[string]string)
	for _, img := range dscOLD.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			return fmt.Errorf("failed to create partial MachO for image %s: %v", img.Name, err)
		}
		dylib2verOLD[img.Name] = m.SourceVersion().Version.String()
	}

	dscNEW, err := dyld.Open(newDSCes[0])
	if err != nil {
		return fmt.Errorf("failed to open DSC: %v", err)
	}
	defer dscNEW.Close()

	image, err = dscNEW.Image("WebKit")
	if err != nil {
		return fmt.Errorf("image not in %s: %v", newDSCes[0], err)
	}

	m, err = image.GetPartialMacho()
	if err != nil {
		return err
	}

	d.New.Webkit = m.SourceVersion().Version.String()

	dylib2verNEW := make(map[string]string)
	for _, img := range dscNEW.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			return fmt.Errorf("failed to create partial MachO for image %s: %v", img.Name, err)
		}
		dylib2verNEW[img.Name] = m.SourceVersion().Version.String()
	}

	var new []string
	var gone []string

	for d1, v1 := range dylib2verOLD {
		if _, ok := dylib2verNEW[d1]; !ok {
			gone = append(gone, fmt.Sprintf("`%s`\t(%s)", d1, v1))
		}
	}

	sort.Strings(gone)

	var deltas []utils.MachoVersion
	for d2, v2 := range dylib2verNEW {
		if v1, ok := dylib2verOLD[d2]; ok {
			if v1 != v2 {
				verdiff, err := utils.DiffVersion(v2, v1)
				if err != nil {
					return err
				}
				deltas = append(deltas, utils.MachoVersion{
					Name:    d2,
					Version: verdiff,
				})
				// fmt.Printf("%s\t(%s -> %s) %s\n", d2, v2, v1, verdiff)
			}
		} else {
			new = append(new, fmt.Sprintf("`%s`\t(%s)", d2, v2))
		}
	}

	sort.Strings(new)

	buf := bytes.NewBufferString("")
	if len(new) > 0 {
		buf.WriteString("### 🆕 dylibs\n\n")
		for _, d := range new {
			buf.WriteString(fmt.Sprintf("- %s\n", d))
		}
	}
	if len(gone) > 0 {
		buf.WriteString("\n### ❌ removed dylibs\n\n")
		for _, d := range gone {
			buf.WriteString(fmt.Sprintf("- %s\n", d))
		}
	}
	if len(deltas) > 0 {
		buf.WriteString("\n### ⬆️ (delta) updated dylibs\n\n")
		utils.SortMachoVersions(deltas)
		w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
		var prev string
		for _, d := range deltas {
			if len(prev) > 0 && prev != d.Version {
				fmt.Fprintf(w, "\n---\n\n")
			}
			fmt.Fprintf(w, "- (%s)\t`%s`  \n", d.Version, d.Name)
			prev = d.Version
		}
		w.Flush()
	}

	d.Dylibs = buf.String()

	return nil
}

func (d *Diff) parseEntitlements() (string, error) {
	oldDB, err := ent.GetDatabase(d.Old.IPSWPath, filepath.Join(d.tmpDir, filepath.Base(d.Old.IPSWPath+".entDB")))
	if err != nil {
		return "", err
	}

	newDB, err := ent.GetDatabase(d.New.IPSWPath, filepath.Join(d.tmpDir, filepath.Base(d.New.IPSWPath+".entDB")))
	if err != nil {
		return "", err
	}

	return ent.DiffDatabases(oldDB, newDB, &ent.Config{
		Markdown: true,
		Color:    false,
		DiffTool: "git",
	})
}
