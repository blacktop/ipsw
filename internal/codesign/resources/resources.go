package resources

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"

	pl "github.com/blacktop/ipsw/pkg/plist"
)

const libraryDirectory = "Contents/Library"
const resourcesDirectory = "Contents/Resources"
const frameworksDirectory = "Contents/Frameworks"
const CodeResourcesPath = "Contents/_CodeSignature/CodeResources"

type hash2 struct {
	CDHash      []byte `plist:"cdhash,omitempty" xml:"cdhash,omitempty"`
	Requirement string `plist:"requirement,omitempty" xml:"requirement,omitempty"`
	Hash2       []byte `plist:"hash2,omitempty" xml:"hash2,omitempty"`
	Symlink     string `plist:"symlink,omitempty" xml:"symlink,omitempty"`
	Optional    bool   `plist:"optional,omitempty" xml:"optional,omitempty"`
}

type CodeResources struct {
	Files  map[string][]byte `plist:"files,omitempty" xml:"files,omitempty"`
	Files2 map[string]hash2  `plist:"files2,omitempty" xml:"files2,omitempty"`
	Rules  map[string]any    `plist:"rules,omitempty" xml:"rules,omitempty"`
	Rules2 map[string]any    `plist:"rules2,omitempty" xml:"rules2,omitempty"`
}

func CreateCodeResources(dir string) error {
	cr := &CodeResources{
		Files:  make(map[string][]byte),
		Files2: make(map[string]hash2),
		Rules:  make(map[string]any),
		Rules2: make(map[string]any),
	}
	// rules
	cr.Rules["^Resources/"] = true
	cr.Rules["^Resources/.*\\.lproj/"] = struct {
		Optional bool    `plist:"optional,omitempty" xml:"optional,omitempty"`
		Weight   float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Optional: true,
		Weight:   1000,
	}
	cr.Rules["^Resources/.*\\.lproj/locversion.plist$"] = struct {
		Omit   bool    `plist:"omit,omitempty" xml:"omit,omitempty"`
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Omit:   true,
		Weight: 1100,
	}
	cr.Rules["^Resources/Base\\.lproj/"] = struct {
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Weight: 1010,
	}
	cr.Rules["^version.plist$"] = true
	// rules2
	cr.Rules2[".*\\.dSYM($|/)"] = struct {
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Weight: 11,
	}
	cr.Rules2["^(.*/)?\\.DS_Store$"] = struct {
		Omit   bool    `plist:"omit,omitempty" xml:"omit,omitempty"`
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Omit:   true,
		Weight: 2000,
	}
	cr.Rules2["^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/"] = struct {
		Nested bool    `plist:"nested,omitempty" xml:"nested,omitempty"`
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Nested: true,
		Weight: 10,
	}
	cr.Rules2["^.*"] = true
	cr.Rules2["^Info\\.plist$"] = struct {
		Omit   bool    `plist:"omit,omitempty" xml:"omit,omitempty"`
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Omit:   true,
		Weight: 20,
	}
	cr.Rules2["^PkgInfo$"] = struct {
		Omit   bool    `plist:"omit,omitempty" xml:"omit,omitempty"`
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Omit:   true,
		Weight: 20,
	}
	cr.Rules2["^Resources/"] = struct {
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Weight: 20,
	}
	cr.Rules2["^Resources/.*\\.lproj/"] = struct {
		Optional bool    `plist:"optional,omitempty" xml:"optional,omitempty"`
		Weight   float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Optional: true,
		Weight:   1000,
	}
	cr.Rules2["^Resources/.*\\.lproj/locversion.plist$"] = struct {
		Omit   bool    `plist:"omit,omitempty" xml:"omit,omitempty"`
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Omit:   true,
		Weight: 1100,
	}
	cr.Rules2["^Resources/Base\\.lproj/"] = struct {
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Weight: 1010,
	}
	cr.Rules2["^[^/]+$"] = struct {
		Nested bool    `plist:"nested,omitempty" xml:"nested,omitempty"`
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Nested: true,
		Weight: 10,
	}
	cr.Rules2["^embedded\\.provisionprofile$"] = struct {
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Weight: 20,
	}
	cr.Rules2["^version\\.plist$"] = struct {
		Weight float64 `plist:"weight,omitempty" xml:"weight,omitempty"`
	}{
		Weight: 20,
	}

	if err := filepath.WalkDir(filepath.Join(dir, frameworksDirectory), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(filepath.Join(dir, "Contents"), path)
		if err != nil {
			return err
		}

		var fwpath string
		if regexp.MustCompile(`^Frameworks/[^/]+\.framework/.+Info\.plist$`).MatchString(relPath) {
			dat, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			ainfo, err := pl.ParseAppInfo(dat)
			if err != nil {
				return fmt.Errorf("failed to parse %s: %w", path, err)
			}
			if ainfo.CFBundleExecutable != "" {
				before, _, ok := strings.Cut(path, ".framework/")
				if ok {
					fwpath = filepath.Join(before+".framework/", ainfo.CFBundleExecutable)
				}
			}
		} else {
			return nil
		}

		if _, ok := cr.Files2[fwpath]; ok {
			return nil // already added
		}

		// files
		var m *macho.File
		if fat, err := macho.OpenFat(fwpath); err == nil { // UNIVERSAL MACHO
			defer fat.Close()
			m = fat.Arches[len(fat.Arches)-1].File
		} else { // SINGLE MACHO ARCH
			if errors.Is(err, macho.ErrNotFat) {
				m, err = macho.Open(fwpath)
				if err != nil {
					return nil
					// return err
				}
				defer m.Close()
			} else {
				return nil // not a macho file
			}
		}
		cs := m.CodeSignature()
		if cs == nil {
			return fmt.Errorf("no code signature in %s", path)
		}
		if len(cs.CodeDirectories) == 0 {
			return fmt.Errorf("no code directory in %s", path)
		}
		cdhashBytes, err := hex.DecodeString(cs.CodeDirectories[len(cs.CodeDirectories)-1].CDHash)
		if err != nil {
			return err
		}
		var requirement string
		if len(cs.Requirements) > 0 {
			requirement = cs.Requirements[0].Detail
		}
		relPath, err = filepath.Rel(filepath.Join(dir, "Contents"), fwpath)
		if err != nil {
			return err
		}
		cr.Files2[filepath.Dir(relPath)] = hash2{
			CDHash:      cdhashBytes[:20],
			Requirement: requirement,
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk %s: %w", filepath.Join(dir, "Resources"), err)
	}
	// TODO: walk pluginsDirectory ??
	// TODO: walk xpcServicesDirectory ??
	// TODO: walk helpersDirectory ??
	if err := filepath.WalkDir(filepath.Join(dir, libraryDirectory), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(filepath.Join(dir, "Contents"), path)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("file %s does not exist", path)
		}
		var symlink string
		if (fi.Mode() & os.ModeSymlink) != 0 {
			symlink, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("failed to eval symlink %s: %w", path, err)
			}
		}
		if symlink != "" {
			cr.Files2[relPath] = hash2{Symlink: symlink}
		} else {
			if d.IsDir() {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return err
			}
			cr.Files2[relPath] = hash2{Hash2: h.Sum(nil)}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk %s: %w", filepath.Join(dir, "Resources"), err)
	}
	if err := filepath.WalkDir(filepath.Join(dir, resourcesDirectory), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(filepath.Join(dir, "Contents"), path)
		if err != nil {
			return err
		}
		// files
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		cr.Files[relPath] = h.Sum(nil)
		f.Seek(0, io.SeekStart) // rewind
		// files2
		h = sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		cr.Files2[relPath] = hash2{Hash2: h.Sum(nil)}
		if err := f.Close(); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk %s: %w", filepath.Join(dir, "Resources"), err)
	}

	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, CodeResourcesPath)), 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", filepath.Dir(filepath.Join(dir, CodeResourcesPath)), err)
	}
	f, err := os.Create(filepath.Join(dir, CodeResourcesPath))
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", CodeResourcesPath, err)
	}
	defer f.Close()

	enc := plist.NewEncoder(f)
	enc.Indent("\t")
	return enc.Encode(cr)
}
