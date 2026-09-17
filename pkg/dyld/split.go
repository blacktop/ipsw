//go:build darwin && cgo

package dyld

/*
#cgo CFLAGS: -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
#cgo CFLAGS: -Wno-nullability-completeness
#cgo LDFLAGS: -ldl
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <dlfcn.h>
int
dsc_extract(void *f, const char* shared_cache_file_path, const char* extraction_root_path){
    int (*extractor_proc)(const char* shared_cache_file_path, const char* extraction_root_path,
                          void (^progress)(unsigned current, unsigned total));
    extractor_proc = f;
    int result = (*extractor_proc)(shared_cache_file_path, extraction_root_path,
                                   ^(unsigned c, unsigned total) { printf("%d/%d\n", c, total); });
    return result;
}
*/
import "C"

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

// firstArm64eXExtractorVersion is the LC_SOURCE_VERSION major of the dsc_extractor.bundle in
// Xcode 27.0, the first release that splits arm64e_x* caches. Xcode 26.x ships dyld-1378, which
// rejects them with "unrecognized dyld shared cache magic".
const firstArm64eXExtractorVersion = 27000

// LibHandle represents an open handle to a library
type LibHandle struct {
	Handle  unsafe.Pointer
	Libname string
}

type XCodeInfoPlist struct {
	ExtractorVersion string    `plist:"DSC Extractor Version,omitempty"`
	DateCollected    time.Time `plist:"DateCollected,omitempty"`
	XCodeVersion     string    `plist:"Version,omitempty"`
}

// GetHandle returns a handle to a library
func GetHandle(libs []string) *LibHandle {
	for _, name := range libs {
		libname := C.CString(name)
		defer C.free(unsafe.Pointer(libname))
		handle := C.dlopen(libname, C.RTLD_LAZY)
		if handle != nil {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Using bundle: %s", name))
			h := &LibHandle{
				Handle:  handle,
				Libname: name,
			}
			return h
		}
	}
	return nil
}

// GetSymbolPointer takes a symbol name and returns a pointer to the symbol.
func (l *LibHandle) GetSymbolPointer(symbol string) (unsafe.Pointer, error) {
	sym := C.CString(symbol)
	defer C.free(unsafe.Pointer(sym))

	C.dlerror()
	p := C.dlsym(l.Handle, sym)
	e := C.dlerror()
	if e != nil {
		return nil, fmt.Errorf("error resolving symbol %q: %v", symbol, errors.New(C.GoString(e)))
	}

	return p, nil
}

// Close closes a LibHandle.
func (l *LibHandle) Close() error {
	C.dlerror()
	C.dlclose(l.Handle)
	e := C.dlerror()
	if e != nil {
		return fmt.Errorf("error closing %v: %v", l.Libname, errors.New(C.GoString(e)))
	}

	return nil
}

// Split extracts all the dyld_shared_cache libraries
func Split(dyldSharedCachePath, destinationPath, xcodePath string, xcodeCache bool) error {
	xcodePathProvided := len(xcodePath) > 0
	if !xcodePathProvided {
		var err error
		xcodePath, err = utils.GetXCodePath()
		if err != nil {
			return fmt.Errorf("failed to get Xcode path: %v", err)
		}
	}
	xcodePath = filepath.Clean(xcodePath)
	if !strings.HasSuffix(xcodePath, "/Contents/Developer") {
		xcodePath = filepath.Join(xcodePath, "Contents/Developer")
	}

	dscExtractorPath := filepath.Join(xcodePath, "Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle")
	_, err := os.Stat(dscExtractorPath)
	if err != nil {
		err_msg := "failed to find DSC extractor library in %s"
		if !xcodePathProvided {
			err_msg += " (use --xcode to specify the path to Xcode)"
		}
		return fmt.Errorf(err_msg, dscExtractorPath)
	}

	dscExtractor := GetHandle([]string{dscExtractorPath})
	if dscExtractor == nil {
		err_msg := "unable to open a handle to the DSC extractor library in %s"
		if !xcodePathProvided {
			err_msg += " (use --xcode to specify the path to Xcode)"
		}

		return fmt.Errorf(err_msg, dscExtractorPath)
	}

	var xcodeVersion string
	symbolsPath := destinationPath
	if xcodeCache {
		xcodeApp := strings.TrimSuffix(xcodePath, "/Contents/Developer")
		xcodeVersion, err = utils.GetXCodeVersion(xcodeApp)
		if err != nil {
			return fmt.Errorf("failed to get Xcode version of %s: %v", xcodeApp, err)
		}
		symbolsPath = filepath.Join(destinationPath, "Symbols")
	}

	extractorProc, err := dscExtractor.GetSymbolPointer("dyld_shared_cache_extract_dylibs_progress")
	if err != nil {
		return fmt.Errorf("failed to get symbol 'dyld_shared_cache_extract_dylibs_progress' pointer: %v", err)
	}

	dscPath := C.CString(dyldSharedCachePath)
	defer C.free(unsafe.Pointer(dscPath))

	destPath := C.CString(symbolsPath)
	defer C.free(unsafe.Pointer(destPath))

	result := C.dsc_extract(extractorProc, dscPath, destPath)
	if result != 0 {
		return splitFailure(dyldSharedCachePath, dscExtractor.Libname, int(result))
	}

	if xcodeCache {
		extractorVersion, err := extractorSourceVersion(dscExtractor.Libname)
		if err != nil {
			return err
		}
		info := XCodeInfoPlist{
			ExtractorVersion: extractorVersion.String(),
			DateCollected:    time.Now(),
			XCodeVersion:     xcodeVersion,
		}
		err = writeDeviceSupportCache(dyldSharedCachePath, destinationPath, symbolsPath, info)
		if err != nil {
			return err
		}
	}

	if err := dscExtractor.Close(); err != nil {
		return fmt.Errorf("failed to close dylib %s: %v", dscExtractor.Libname, err)
	}

	return nil
}

// splitFailure explains a non-zero dsc_extractor result. Apple's extractor only reports failures
// on stderr, so the cache magic and bundle version are added to make the cause visible.
func splitFailure(dscPath, bundlePath string, result int) error {
	msg := fmt.Sprintf("dsc_extractor.bundle %s failed to split %s: returned %d",
		bundlePath, dscPath, result)
	magic, err := readCacheMagic(dscPath)
	if err != nil {
		return fmt.Errorf("%s (%v)", msg, err)
	}
	version, err := extractorSourceVersion(bundlePath)
	if err != nil {
		return fmt.Errorf("%s (magic %q; %v)", msg, magic, err)
	}
	return fmt.Errorf("%s (magic %q, bundle version %s)%s",
		msg, magic, version, splitHint(magic, version))
}

func splitHint(cacheMagic string, bundleVersion types.SrcVersion) string {
	bundleMajor := bundleVersion >> 40
	if bundleMajor >= firstArm64eXExtractorVersion {
		return ""
	}
	if !strings.HasPrefix(cacheMagic, "dyld_v1arm64ex") {
		return ""
	}
	return "; this bundle predates Xcode 27, which added support for arm64e_x* caches" +
		" (use --xcode to select Xcode 27 or newer)"
}

// extractorSourceVersion reads the LC_SOURCE_VERSION of the dsc_extractor.bundle at bundlePath.
func extractorSourceVersion(bundlePath string) (types.SrcVersion, error) {
	var m *macho.File
	fat, err := macho.OpenFat(bundlePath)
	switch err {
	case nil:
		defer fat.Close()
		if len(fat.Arches) == 0 {
			return 0, fmt.Errorf("fat mach-o %s has no architectures", bundlePath)
		}
		m = fat.Arches[0].File
	case macho.ErrNotFat:
		m, err = macho.Open(bundlePath)
		if err != nil {
			return 0, fmt.Errorf("failed to open mach-o %s: %v", bundlePath, err)
		}
		defer m.Close()
	default:
		return 0, fmt.Errorf("failed to open fat mach-o %s: %v", bundlePath, err)
	}
	sv := m.SourceVersion()
	if sv == nil {
		return 0, fmt.Errorf("%s has no LC_SOURCE_VERSION", bundlePath)
	}
	return sv.Version, nil
}

// readCacheMagic reads only the 16-byte magic (not the full header via ReadHeader) so a
// truncated or garbage cache still yields a useful failure message.
func readCacheMagic(dscPath string) (string, error) {
	f, err := os.Open(dscPath)
	if err != nil {
		return "", fmt.Errorf("failed to open dyld_shared_cache %s: %w", dscPath, err)
	}
	defer f.Close()

	var m magic
	if _, err := io.ReadFull(f, m[:]); err != nil {
		return "", fmt.Errorf("failed to read dyld_shared_cache magic from %s: %w", dscPath, err)
	}
	return m.String(), nil
}

// writeDeviceSupportCache completes an Xcode "iOS DeviceSupport" layout after a successful split
// by writing Info.plist and copying the cache files next to the extracted Symbols.
func writeDeviceSupportCache(
	dscPath, destinationPath, symbolsPath string, info XCodeInfoPlist,
) error {
	dscCopyPath := filepath.Join(symbolsPath, "private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/")
	if err := os.MkdirAll(dscCopyPath, 0750); err != nil {
		return fmt.Errorf("failed to create output directory %s: %v", dscCopyPath, err)
	}

	data, err := plist.MarshalIndent(info, plist.XMLFormat, "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal Xcode cache Info.plist: %v", err)
	}
	infoPlistPath := filepath.Join(destinationPath, "Info.plist")
	if err := os.WriteFile(infoPlistPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %v", infoPlistPath, err)
	}

	matches, err := filepath.Glob(filepath.Join(filepath.Dir(dscPath), "dyld_shared_cache_*"))
	if err != nil {
		return fmt.Errorf("failed to glob dyld_shared_cache_*: %v", err)
	}
	for _, match := range matches {
		f, err := os.Create(filepath.Join(dscCopyPath, ".copied_"+filepath.Base(match)))
		if err != nil {
			return fmt.Errorf("failed to create .copied_%s: %v", match, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close %s: %v", f.Name(), err)
		}
		if err := utils.Copy(match, filepath.Join(dscCopyPath, filepath.Base(match))); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %v", match, dscCopyPath, err)
		}
	}
	return nil
}
