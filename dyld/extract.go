// +build cgo

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
	int (*extractor_proc)(const char* shared_cache_file_path,
		                  const char* extraction_root_path,
                          void (^progress)(unsigned current, unsigned total));
	extractor_proc = (int (*)(const char *))f;
	int result = (*extractor_proc)(shared_cache_file_path,
		                           extraction_root_path,
							       ^(unsigned c, unsigned total) { printf("%d/%d\n", c, total); });
    return result;
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
)

// LibHandle represents an open handle to a library
type LibHandle struct {
	Handle  unsafe.Pointer
	Libname string
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
func Split(dyldSharedCachePath, destinationPath, operatingSystem string) error {

	var bundles []string

	switch operatingSystem {
	case "iPhoneOS":
		bundles = []string{
			"/Applications/Xcode-beta.app/Contents/Developer/Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle",
			"/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle",
		}
	case "AppleTVOS":
		bundles = []string{
			"/Applications/Xcode-beta.app/Contents/Developer/Platforms/AppleTVOS.platform/usr/lib/dsc_extractor.bundle",
			"/Applications/Xcode.app/Contents/Developer/Platforms/AppleTVOS.platform/usr/lib/dsc_extractor.bundle",
		}
	case "WatchOS":
		bundles = []string{
			"/Applications/Xcode-beta.app/Contents/Developer/Platforms/WatchOS.platform/usr/lib/dsc_extractor.bundle",
			"/Applications/Xcode.app/Contents/Developer/Platforms/WatchOS.platform/usr/lib/dsc_extractor.bundle",
		}
	}

	dscExtractor, err := GetHandle(bundles)
	if err != nil {
		return errors.Wrapf(err, "failed to split %s", dyldSharedCachePath)
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
