//go:build darwin && cgo && objc

package objc

/*
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <objc/objc-runtime.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type Image uintptr

func LoadImage(name string) (Image, error) {
	libname := C.CString(name)
	defer C.free(unsafe.Pointer(libname))

	this_lib := C.dlopen(libname, C.RTLD_NOW)
	if this_lib == nil {
		return 0, fmt.Errorf("unable to open a handle to the library: %s", C.GoString(C.dlerror()))
	}

	return (Image)(unsafe.Pointer(this_lib)), nil
}

func (i Image) Close() {
	C.dlclose(unsafe.Pointer(i))
}

func ImageNames() (imageNames []string) {
	var outCount uint
	var coutCount C.uint

	imageNameList := C.objc_copyImageNames(&coutCount)
	defer C.free(unsafe.Pointer(imageNameList))

	if outCount = uint(coutCount); outCount > 0 {
		imageNames = make([]string, outCount)

		for i, elem := uint(0), imageNameList; i < outCount; i++ {
			imageNames[i] = C.GoString(*elem)
			elem = nextString(elem)
		}
	}

	return
}

func ClassNamesForImage(image string) (classNames []string) {
	var outCount uint
	var coutCount C.uint

	cimage := C.CString(image)
	defer C.free(unsafe.Pointer(cimage))

	classNameList := C.objc_copyClassNamesForImage(cimage, &coutCount)
	defer C.free(unsafe.Pointer(classNameList))

	if outCount = uint(coutCount); outCount > 0 {
		classNames = make([]string, outCount)

		for i, elem := uint(0), classNameList; i < outCount; i++ {
			classNames[i] = C.GoString(*elem)
			elem = nextString(elem)
		}
	}

	return
}

func nextString(list **C.char) **C.char {
	ptr := uintptr(unsafe.Pointer(list)) + unsafe.Sizeof(*list)
	return (**C.char)(unsafe.Pointer(ptr))
}
