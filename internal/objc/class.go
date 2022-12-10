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
	"unsafe"
)

type Class uintptr

func GetClass(name string) Class {
	return (Class)(unsafe.Pointer(C.objc_getClass(C.CString(name))))
}

func ClassList() (classes []Class) {
	var outCount C.uint
	var classPointers []C.Class
	p := (C.objc_copyClassList(&outCount))
	result := make([]Class, outCount)
	if p != nil {
		classPointers = (*[1 << 30]C.Class)(unsafe.Pointer(p))[0:outCount]
		for i := 0; i < int(outCount); i++ {
			result[i] = (Class)(unsafe.Pointer(classPointers[i]))
		}
		C.free(unsafe.Pointer(p))
	}
	return result
}

func GetMetaClass(name string) Class {
	return (Class)(unsafe.Pointer(C.objc_getMetaClass(C.CString(name))))
}

func (cls Class) cclass() C.Class {
	return (C.Class)(unsafe.Pointer(cls))
}

func (cls Class) cid() C.id {
	return (C.id)(unsafe.Pointer(cls))
}

func (cls Class) Name() string {
	return C.GoString(C.class_getName(cls.cclass()))
}

func (cls Class) Super() Class {
	return (Class)(unsafe.Pointer(C.class_getSuperclass(cls.cclass())))
}

func (cls Class) IsMetaClass() bool {
	return bool(C.class_isMetaClass(cls.cclass()))
}

func (cls Class) InstanceSize() int {
	return int(C.class_getInstanceSize(cls.cclass()))
}

func (cls Class) ClassVariable(name string) Ivar {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	return (Ivar)(unsafe.Pointer(C.class_getClassVariable(cls.cclass(), cname)))
}

// func (cls Class) AddIvar(name string, size uint, alignment uint8, types string) bool {
// 	cname := C.CString(name)
// 	defer C.free(unsafe.Pointer(cname))

// 	ctypes := C.CString(types)
// 	defer C.free(unsafe.Pointer(ctypes))

// 	return C.class_addIvar(cls.cclass(), cname, C.size_t(size), C.uint8_t(alignment), ctypes) != 0
// }

func (cls Class) Ivar(name string) Ivar {
	return (Ivar)(unsafe.Pointer(C.class_getInstanceVariable(cls.cclass(), C.CString(name))))
}

func (cls Class) Ivars() []Ivar {
	var outCount C.uint
	var ivarPointers []C.Ivar
	p := (C.class_copyIvarList(cls.cclass(), &outCount))
	result := make([]Ivar, outCount)
	if p != nil {
		ivarPointers = (*[1 << 30]C.Ivar)(unsafe.Pointer(p))[0:outCount]
		for i := 0; i < int(outCount); i++ {
			result[i] = (Ivar)(unsafe.Pointer(ivarPointers[i]))
		}
		C.free(unsafe.Pointer(p))
	}
	return result
}

func (cls Class) Method(name string) Method {
	sel := C.sel_registerName(C.CString(name))
	return (Method)(unsafe.Pointer(C.class_getClassMethod(cls.cclass(), sel)))
}

func (cls Class) InstanceMethod(name Sel) Method {
	return (Method)(unsafe.Pointer(C.class_getInstanceMethod(cls.cclass(), name.csel())))
}

func (cls Class) GetMethodImplementation(name Sel) C.IMP {
	return C.IMP(C.class_getMethodImplementation(cls.cclass(), name.csel()))
}

func (cls Class) RespondsToSelector(sel Sel) bool {
	return bool(C.class_respondsToSelector(cls.cclass(), sel.csel()))
}

func (cls Class) Methods() []Method {
	var outCount C.uint
	var methodPointers []C.Method
	p := (C.class_copyMethodList(cls.cclass(), &outCount))
	result := make([]Method, outCount)
	if p != nil {
		methodPointers = (*[1 << 30]C.Method)(unsafe.Pointer(p))[0:outCount]
		for i := 0; i < int(outCount); i++ {
			result[i] = (Method)(unsafe.Pointer(methodPointers[i]))
		}
		C.free(unsafe.Pointer(p))
	}
	return result
}

func (cls Class) Property(name string) Property {
	return (Property)(unsafe.Pointer(C.class_getProperty(cls.cclass(), C.CString(name))))
}

func (cls Class) Properties() []Property {
	var outCount C.uint
	var properties []C.objc_property_t
	p := (C.class_copyPropertyList(cls.cclass(), &outCount))
	result := make([]Property, outCount)
	if p != nil {
		properties = (*[1 << 30]C.objc_property_t)(unsafe.Pointer(p))[0:outCount]
		for i := 0; i < int(outCount); i++ {
			result[i] = (Property)(unsafe.Pointer(properties[i]))
		}
		C.free(unsafe.Pointer(p))
	}
	return result
}

// func (cls Class) AddMethod(name Sel, imp Imp, types string) bool {
// 	ctype := C.CString(types)
// 	defer C.free(unsafe.Pointer(ctype))

// 	return C.class_addMethod(cls, name, imp, ctype) != 0
// }

// func (cls Class) ReplaceMethod(name Sel, imp Imp, types string) Imp {
// 	ctype := C.CString(types)
// 	defer C.free(unsafe.Pointer(ctype))

// 	return Imp(C.class_replaceMethod(cls, name, imp, ctype))
// }

// func (cls Class) AddProtocol(protocol Protocol) bool {
// 	return C.class_addProtocol(cls, protocol) != 0
// }

// func (cls Class) AddProperty(name string, attributes []PropertyAttribute) bool {
// 	var cattributes *C.objc_property_attribute_t

// 	cname := C.CString(name)
// 	defer C.free(unsafe.Pointer(cname))

// 	attrSize := unsafe.Sizeof(*cattributes)
// 	attributeCount := len(attributes)

// 	if len(attributes) != 0 {
// 		cattributes = (*C.objc_property_attribute_t)(calloc(uint(attributeCount), attrSize))

// 		defer func(cattributes *C.objc_property_attribute_t, attributeCount int) {
// 			for i, elem := 0, cattributes; i < attributeCount; i++ {
// 				C.free(unsafe.Pointer(elem.name))
// 				C.free(unsafe.Pointer(elem.value))

// 				elem = nextPropertyAttr(elem)
// 			}

// 			C.free(unsafe.Pointer(cattributes))
// 		}(cattributes, attributeCount)

// 		for i, elem := 0, cattributes; i < attributeCount; i++ {
// 			attr := attributes[i]
// 			elem.name = C.CString(attr.Name)
// 			elem.value = C.CString(attr.Value)
// 			elem = nextPropertyAttr(elem)
// 		}
// 	}

// 	return C.class_addProperty(cls, cname, cattributes, C.uint(attributeCount)) != 0
// }

// func (cls Class) ReplaceProperty(name string, attributes []PropertyAttribute) {
// 	var cattributes *C.objc_property_attribute_t

// 	cname := C.CString(name)
// 	defer C.free(unsafe.Pointer(cname))

// 	attrSize := unsafe.Sizeof(*cattributes)
// 	attributeCount := len(attributes)

// 	if len(attributes) != 0 {
// 		cattributes = (*C.objc_property_attribute_t)(calloc(uint(attributeCount), attrSize))

// 		defer func(cattributes *C.objc_property_attribute_t, attributeCount int) {
// 			for i, elem := 0, cattributes; i < attributeCount; i++ {
// 				C.free(unsafe.Pointer(elem.name))
// 				C.free(unsafe.Pointer(elem.value))

// 				elem = nextPropertyAttr(elem)
// 			}

// 			C.free(unsafe.Pointer(cattributes))
// 		}(cattributes, attributeCount)

// 		for i, elem := 0, cattributes; i < attributeCount; i++ {
// 			attr := attributes[i]
// 			elem.name = C.CString(attr.Name)
// 			elem.value = C.CString(attr.Value)
// 			elem = nextPropertyAttr(elem)
// 		}
// 	}

// 	C.class_replaceProperty(cls, cname, cattributes, C.uint(attributeCount))
// }

func (cls Class) ConformsToProtocol(prot Protocol) bool {
	return bool(C.class_conformsToProtocol(cls.cclass(), prot.cprot()))
}

func (cls Class) Version() int {
	return int(C.class_getVersion(cls.cclass()))
}

func (cls Class) SetVersion(version int) {
	C.class_setVersion(cls.cclass(), C.int(version))
}

func (cls Class) CreateInstance(extraBytes uint) Id {
	return (Id)(unsafe.Pointer(C.class_createInstance(cls.cclass(), C.size_t(extraBytes))))
}

func (cls Class) GetImageName() string {
	return C.GoString(C.class_getImageName(cls.cclass()))
}
