package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

type kernel struct {
	Path    string
	Version *kernelcache.Version
}

type Context struct {
	IPSWPath  string
	Info      *info.Info
	Version   string
	Build     string
	Folder    string
	MountPath string
	Kernel    kernel
	DSC       string
	Webkit    string
}

type Diff struct {
	Title  string
	Old    Context
	New    Context
	Kexts  string
	Dylibs string
	Ents   string
}

func New(title, ipswOld, ipswNew string) *Diff {
	return &Diff{
		Title: title,
		Old: Context{
			IPSWPath: ipswOld,
		},
		New: Context{
			IPSWPath: ipswNew,
		},
	}
}

// Diff diffs the diff
func (d *Diff) Diff() (err error) {

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
	d.New.Version = d.New.Info.Plists.BuildManifest.ProductVersion
	d.New.Build = d.New.Info.Plists.BuildManifest.ProductBuildVersion
	d.New.Folder, err = d.New.Info.GetFolder()
	if err != nil {
		log.Errorf("failed to get folder from 'New' IPSW metadata: %v", err)
	}

	if d.Title == "" {
		d.Title = fmt.Sprintf("%s (%s) .vs %s (%s)", d.Old.Version, d.Old.Build, d.New.Version, d.New.Build)
	}

	tmpDir, err := os.MkdirTemp(os.TempDir(), "ipsw-diff")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := kernelcache.Extract(d.Old.IPSWPath, filepath.Join(tmpDir, d.Old.Folder)); err != nil {
		return fmt.Errorf("failed to extract kernelcaches from 'Old' IPSW: %v", err)
	}
	if err := kernelcache.Extract(d.New.IPSWPath, filepath.Join(tmpDir, d.New.Folder)); err != nil {
		return fmt.Errorf("failed to extract kernelcaches from 'New' IPSW: %v", err)
	}

	for kmodel := range d.Old.Info.Plists.GetKernelCaches() {
		kcache1 := d.Old.Info.Plists.GetKernelCaches()[kmodel][0]
		kcache2 := d.New.Info.Plists.GetKernelCaches()[kmodel][0]
		d.Old.Kernel.Path = filepath.Join(tmpDir, d.Old.Folder, d.Old.Info.GetKernelCacheFileName(kcache1))
		d.New.Kernel.Path = filepath.Join(tmpDir, d.New.Folder, d.New.Info.GetKernelCacheFileName(kcache2))
		break // just use first kernelcache for now
	}

	// get kernelcache versions
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
	kextsOld, err := kernelcache.KextList(d.Old.Kernel.Path, true)
	if err != nil {
		return err
	}
	kextsNew, err := kernelcache.KextList(d.New.Kernel.Path, true)
	if err != nil {
		return err
	}
	out, err := utils.GitDiff(
		strings.Join(kextsOld, "\n")+"\n",
		strings.Join(kextsNew, "\n")+"\n",
		&utils.GitDiffConfig{Color: false, Tool: "git"})
	if err != nil {
		return err
	}
	if len(out) == 0 {
		d.Kexts = "- No differences found"
	} else {
		d.Kexts = "```diff\n" + out + "\n```" // FIXME: why is git adding `&#43;` instead of `+`?
	}

	// TODO: mount SystemOS volumes and get DSC paths

	return nil
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
