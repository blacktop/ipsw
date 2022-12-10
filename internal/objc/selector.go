package objc

// #include <stdlib.h>
// #include <objc/runtime.h>
import "C"
import "unsafe"

type Sel uintptr

func (s Sel) csel() C.SEL {
	return (C.SEL)(unsafe.Pointer(s))
}

func (s Sel) Name() string {
	return C.GoString(C.sel_getName(s.csel()))
}

func RegisterSelectorName(str string) Sel {
	cstr := C.CString(str)
	defer C.free(unsafe.Pointer(cstr))

	return (Sel)(unsafe.Pointer((C.sel_registerName(cstr))))
}

func GetSelectorUid(str string) Sel {
	cstr := C.CString(str)
	defer C.free(unsafe.Pointer(cstr))

	return (Sel)(unsafe.Pointer((C.sel_getUid(cstr))))
}
