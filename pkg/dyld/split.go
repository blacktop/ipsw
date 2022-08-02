//go:build darwin && cgo

package dyld

/*
#cgo CFLAGS: -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
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
    extractor_proc = (int (*)(const char *))f;
    int result = (*extractor_proc)(shared_cache_file_path, extraction_root_path,
                                   ^(unsigned c, unsigned total) { printf("%d/%d\n", c, total); });
    return result;
}
*/
import "C"

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

var xcodePaths = []string{
	"/Applications/Xcode-beta.app",
	"/Applications/Xcode.app",
}

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
type XCodeAppInfoPlist struct {
	CFBundleShortVersionString string `plist:"CFBundleShortVersionString,omitempty"`
}

// GetHandle returns a handle to a library
func GetHandle(libs []string) (*LibHandle, error) {
	for _, name := range libs {
		libname := C.CString(name)
		defer C.free(unsafe.Pointer(libname))
		handle := C.dlopen(libname, C.RTLD_LAZY)
		if handle != nil {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("using bundle: %s", name))
			h := &LibHandle{
				Handle:  handle,
				Libname: name,
			}
			return h, nil
		}
	}
	return nil, errors.New("unable to open a handle to the library")
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

	var bundles []string

	if len(xcodePath) > 0 {
		xcodePaths = append([]string{xcodePath}, xcodePaths...)
	}

	for _, xpath := range xcodePaths {
		bundles = append(bundles, filepath.Join(xpath, "Contents/Developer/Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle"))
	}

	dscExtractor, err := GetHandle(bundles)
	if err != nil {
		return errors.Wrapf(err, "failed to split %s", dyldSharedCachePath)
	}

	if xcodeCache {
		// get ExtractorVersion
		fat, err := macho.OpenFat(dscExtractor.Libname)
		if err != nil && err != macho.ErrNotFat {
			return fmt.Errorf("failed to open %s: %v", dscExtractor.Libname, err)
		}
		m := fat.Arches[0]
		extVer := "1040.2.2.0.0"
		if m.SourceVersion() != nil {
			extVer = m.SourceVersion().Version
		}
		fat.Close()
		// get XCodeVersion
		xcodeContentPath := strings.TrimSuffix(dscExtractor.Libname, "/Developer/Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle")
		xcodeContentPath = filepath.Join(xcodeContentPath, "Info.plist")
		data, err := ioutil.ReadFile(xcodeContentPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %v", xcodeContentPath, err)
		}
		appInfo := XCodeAppInfoPlist{}
		plist.NewDecoder(bytes.NewReader(data)).Decode(&appInfo)
		xcodeVersion := "14.0"
		if len(appInfo.CFBundleShortVersionString) > 0 {
			xcodeVersion = appInfo.CFBundleShortVersionString
		}
		// write Info.plist
		infoPlistPath := filepath.Join(destinationPath, "Info.plist")
		data, err = plist.MarshalIndent(XCodeInfoPlist{
			ExtractorVersion: extVer,
			DateCollected:    time.Now(),
			XCodeVersion:     xcodeVersion,
		}, plist.XMLFormat, "\t")
		if err != nil {
			return fmt.Errorf("failed to marshal stop session request: %v", err)
		}
		log.Infof("Creating XCode cache %s\n", infoPlistPath)
		ioutil.WriteFile(infoPlistPath, data, 0644)

		destinationPath = filepath.Join(destinationPath, "Symbols")
	}

	extractorProc, err := dscExtractor.GetSymbolPointer("dyld_shared_cache_extract_dylibs_progress")
	if err != nil {
		return errors.Wrapf(err, "failed to split %s", dyldSharedCachePath)
	}

	dscPath := C.CString(dyldSharedCachePath)
	defer C.free(unsafe.Pointer(dscPath))

	destPath := C.CString(destinationPath)
	defer C.free(unsafe.Pointer(destPath))

	result := C.dsc_extract(extractorProc, dscPath, destPath)
	if result != 0 {
		return errors.New("failed to run dsc_extract")
	}

	if err := dscExtractor.Close(); err != nil {
		return errors.Wrapf(err, "failed to close dylib %s", dscExtractor.Libname)
	}

	return nil
}
