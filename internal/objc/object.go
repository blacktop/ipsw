package objc

// #include <stdlib.h>
// #include <objc/runtime.h>
import "C"
import "unsafe"

type Id uintptr

func (obj Id) cid() C.id {
	return (C.id)(unsafe.Pointer(obj))
}

func (obj Id) Method(name string) Method {
	sel := C.sel_registerName(C.CString(name))
	return (Method)(unsafe.Pointer(C.class_getInstanceMethod(obj.Class().cclass(), sel)))
}

func (obj Id) Class() Class {
	return (Class)(unsafe.Pointer(C.object_getClass(obj.cid())))
}

func (obj Id) SetClass(cls Class) Class {
	return (Class)(unsafe.Pointer(C.object_setClass(obj.cid(), cls.cclass())))
}

func (obj Id) Copy(size uint) Id {
	return (Id)(unsafe.Pointer(C.object_copy(obj.cid(), C.size_t(size))))
}

func (obj Id) Dispose() Id {
	return (Id)(unsafe.Pointer(C.object_dispose(obj.cid())))
}

func (obj Id) SetInstanceVariable(name string, val Id) {
	C.object_setInstanceVariable(obj.cid(), C.CString(name), unsafe.Pointer(val))
}

func (obj Id) InstanceVariable(name string) (ivar Ivar, outValue unsafe.Pointer) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	ivar = (Ivar)(unsafe.Pointer(C.object_getInstanceVariable(obj.cid(), cname, &outValue)))
	return
}

func (obj Id) IndexedIvars() unsafe.Pointer {
	return C.object_getIndexedIvars(obj.cid())
}

func (obj Id) Ivar(ivar Ivar) unsafe.Pointer {
	return unsafe.Pointer(C.object_getIvar(obj.cid(), ivar.civar()))
}

func (obj Id) SetIvar(ivar Ivar, value unsafe.Pointer) {
	C.object_setIvar(obj.cid(), ivar.civar(), C.id(value))
}
