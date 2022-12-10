package objc

// #include <stdlib.h>
// #include <objc/runtime.h>
import "C"
import "unsafe"

type Method uintptr

type Imp C.IMP

type MethodDescription struct {
	Name  string
	Types string
}

func (m Method) cmethod() C.Method {
	return (C.Method)(unsafe.Pointer(m))
}

func (m Method) Name() string {
	return C.GoString(C.sel_getName(C.method_getName(m.cmethod())))
}

func (m Method) Implementation() Imp {
	return Imp(C.method_getImplementation(m.cmethod()))
}

func (m Method) TypeEncoding() string {
	return C.GoString(C.method_getTypeEncoding(m.cmethod()))
}

func (m Method) ReturnType() string {
	return C.GoString(C.method_copyReturnType(m.cmethod()))
}

func (m Method) ArgumentType(index int) string {
	return C.GoString(C.method_copyArgumentType(m.cmethod(), C.uint(index)))
}

func (mthd Method) ArgumentCount() int {
	return (int)(C.method_getNumberOfArguments(mthd.cmethod()))
}

func (m Method) Description() MethodDescription {
	return makeMethodDescription(*C.method_getDescription(m.cmethod()))
}

func (m Method) SetImplementation(imp Imp) Imp {
	return Imp(C.method_setImplementation(m.cmethod(), imp))
}

func ExchangeImplementations(m1 Method, m2 Method) {
	C.method_exchangeImplementations(m1.cmethod(), m2.cmethod())
}

func makeMethodDescription(description C.struct_objc_method_description) MethodDescription {
	return MethodDescription{
		Name:  (Sel)(unsafe.Pointer(description.name)).Name(),
		Types: C.GoString(description.types),
	}
}

func nextMethod(list *C.Method) *C.Method {
	ptr := uintptr(unsafe.Pointer(list)) + unsafe.Sizeof(*list)
	return (*C.Method)(unsafe.Pointer(ptr))
}

func nextMethodDescription(list *C.struct_objc_method_description) *C.struct_objc_method_description {
	ptr := uintptr(unsafe.Pointer(list)) + unsafe.Sizeof(*list)
	return (*C.struct_objc_method_description)(unsafe.Pointer(ptr))
}
