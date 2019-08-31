// +build cgo

package dlopen

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
import "C"
import "unsafe"

func DLOpen(filename []byte, flags int32) uintptr {
	return uintptr(C.dlopen((*C.char)(unsafe.Pointer(&filename[0])), C.int(flags)))
}

func DLClose(handle uintptr) int32 {
	return int32(C.dlclose(unsafe.Pointer(handle)))
}

func DLSym(handle uintptr, symbol []byte) uintptr {
	return uintptr(C.dlsym(unsafe.Pointer(handle), (*C.char)(unsafe.Pointer(&symbol[0]))))
}

func DLError() uintptr {
	return uintptr(unsafe.Pointer(C.dlerror()))
}
