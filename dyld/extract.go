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
	int (*extractor_proc)(const char* shared_cache_file_path, const char* extraction_root_path,
                              void (^progress)(unsigned current, unsigned total));
	extractor_proc = (int (*)(const char *))f;
	int result = (*extractor_proc)(shared_cache_file_path, extraction_root_path,
							  ^(unsigned c, unsigned total) { printf("%d/%d\n", c, total); });
	// fprintf(stderr, "dyld_shared_cache_extract_dylibs_progress() => %d\n", result);
    return result;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"log"
	"os"
	"unsafe"
)

const bundle = "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/usr/lib/dsc_extractor.bundle"

// LibHandle represents an open handle to a library
type LibHandle struct {
	Handle  unsafe.Pointer
	Libname string
}

// GetHandle returns a handle to a library
func GetHandle(lib string) (*LibHandle, error) {
	// for _, name := range libs {
	libname := C.CString(lib)
	defer C.free(unsafe.Pointer(libname))
	handle := C.dlopen(libname, C.RTLD_LAZY)
	if handle != nil {
		h := &LibHandle{
			Handle:  handle,
			Libname: lib,
		}
		return h, nil
	}
	// }
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
func Split(dyldSharedCachePath, destinationPath string) error {

	if _, err := os.Stat(bundle); os.IsNotExist(err) {
		return err
	}

	dscExtractor, err := GetHandle(bundle)
	if err != nil {
		log.Fatal(err)
	}

	extractorProc, err := dscExtractor.GetSymbolPointer("dyld_shared_cache_extract_dylibs_progress")
	if err != nil {
		log.Fatal(err)
	}

	dscPath := C.CString(dyldSharedCachePath)
	defer C.free(unsafe.Pointer(dscPath))

	destPath := C.CString(destinationPath)
	defer C.free(unsafe.Pointer(destPath))

	result := C.dsc_extract(extractorProc, dscPath, destPath)
	if result != 0 {
		return errors.New("something went wrong")
	}

	return nil
}
