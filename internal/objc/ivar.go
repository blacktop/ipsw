//go:build darwin && cgo && objc

package objc

// #include <objc/runtime.h>
import "C"
import "unsafe"

type Ivar uintptr

func (ivar Ivar) civar() C.Ivar {
	return (C.Ivar)(unsafe.Pointer(ivar))
}

func (ivar Ivar) Name() string {
	return C.GoString(C.ivar_getName((C.Ivar)(unsafe.Pointer(ivar))))
}

func (ivar Ivar) TypeEncoding() string {
	return C.GoString(C.ivar_getTypeEncoding((C.Ivar)(unsafe.Pointer(ivar))))
}

func nextIvar(list *C.Ivar) *C.Ivar {
	ptr := uintptr(unsafe.Pointer(list)) + unsafe.Sizeof(*list)
	return (*C.Ivar)(unsafe.Pointer(ptr))
}
