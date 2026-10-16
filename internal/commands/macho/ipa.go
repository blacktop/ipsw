package macho

import (
	"archive/zip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/blacktop/ipsw/pkg/plist"
)

const (
	maxIPAInfoSize             = 16 << 20
	maxIPAExecutableSize int64 = 4 << 30
)

// OpenIPAMachO opens an IPA's main executable with the usual architecture selection.
func OpenIPAMachO(ipaPath, arch string) (_ *MachO, err error) {
	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open IPA %q: %w", ipaPath, err)
	}
	defer zr.Close()
	// Only the top-level app selects the executable; embedded bundles cannot.
	var info *zip.File
	for _, f := range zr.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) != 3 || parts[0] != "Payload" || !strings.HasSuffix(parts[1], ".app") || parts[1] == ".app" || parts[2] != "Info.plist" {
			continue
		}
		if info != nil {
			return nil, fmt.Errorf("IPA contains multiple top-level app Info.plists: %q and %q", info.Name, f.Name)
		}
		info = f
	}
	if info == nil {
		return nil, fmt.Errorf("IPA does not contain Payload/<app>.app/Info.plist")
	}
	if !info.Mode().IsRegular() || info.UncompressedSize64 > maxIPAInfoSize {
		return nil, fmt.Errorf("invalid IPA Info.plist %q: expected a regular file of at most %d bytes", info.Name, maxIPAInfoSize)
	}
	infoReader, err := info.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %q: %w", info.Name, err)
	}
	defer infoReader.Close()
	data, err := io.ReadAll(io.LimitReader(infoReader, maxIPAInfoSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", info.Name, err)
	}
	if len(data) > maxIPAInfoSize {
		return nil, fmt.Errorf("IPA Info.plist %q exceeds %d bytes", info.Name, maxIPAInfoSize)
	}
	app, err := plist.ParseAppInfo(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %w", info.Name, err)
	}
	name := app.CFBundleExecutable
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return nil, fmt.Errorf("invalid CFBundleExecutable %q in %q", name, info.Name)
	}
	name = path.Join(path.Dir(info.Name), name)
	var executable *zip.File
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		if executable != nil {
			return nil, fmt.Errorf("IPA contains duplicate executable %q", name)
		}
		executable = f
	}
	if executable == nil {
		return nil, fmt.Errorf("IPA executable %q not found", name)
	}
	if !executable.Mode().IsRegular() || executable.UncompressedSize64 > uint64(maxIPAExecutableSize) {
		return nil, fmt.Errorf("invalid IPA executable %q: expected a regular file of at most %d bytes", name, maxIPAExecutableSize)
	}
	r, err := executable.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open IPA executable %q: %w", executable.Name, err)
	}
	defer r.Close()
	// Mach-O parsing needs random access. Keep only the selected executable on
	// disk, and transfer ownership of that temporary file to the returned MachO.
	tmp, err := os.CreateTemp("", "ipsw-ipa-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			err = errors.Join(err, os.Remove(tmp.Name()))
		}
	}()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(r, maxIPAExecutableSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read IPA executable %q: %w", executable.Name, err)
	}
	if n > maxIPAExecutableSize {
		return nil, fmt.Errorf("IPA executable %q exceeds %d bytes", executable.Name, maxIPAExecutableSize)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	mr, err := OpenMachO(tmp.Name(), arch)
	if err != nil {
		return nil, fmt.Errorf("failed to open IPA executable %q: %w", executable.Name, err)
	}
	mr.temporaryPath = tmp.Name()
	copy(mr.sourceDigest[:], hash.Sum(nil))
	return mr, nil
}
