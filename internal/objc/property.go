package objc

// #include <stdlib.h>
// #include <objc/runtime.h>
import "C"
import "unsafe"

type Property uintptr

type PropertyAttribute struct {
	Name  string
	Value string
}

func (p Property) cprop() C.objc_property_t {
	return (C.objc_property_t)(unsafe.Pointer(p))
}

func (attr PropertyAttribute) ctype() C.objc_property_attribute_t {
	return C.objc_property_attribute_t{
		name:  C.CString(attr.Name),
		value: C.CString(attr.Value),
	}
}

func makePropertyAttribute(attr C.objc_property_attribute_t) PropertyAttribute {
	return PropertyAttribute{
		Name:  C.GoString(attr.name),
		Value: C.GoString(attr.value),
	}
}

func (p Property) Name() string {
	cname := C.property_getName(p.cprop())
	return C.GoString(cname)
}

func (p Property) Attributes() string {
	cattr := C.property_getAttributes(p.cprop())
	return C.GoString(cattr)
}

func (p Property) CopyAttributeValue(attributeName string) string {
	cattrName := C.CString(attributeName)
	defer C.free(unsafe.Pointer(cattrName))

	cattrVal := C.property_copyAttributeValue(p.cprop(), cattrName)
	defer C.free(unsafe.Pointer(cattrVal))

	return C.GoString(cattrVal)
}

func (p Property) CopyAttributeList() (attributes []PropertyAttribute) {
	var coutCount C.uint

	attrList := C.property_copyAttributeList(p.cprop(), &coutCount)
	defer C.free(unsafe.Pointer(attrList))

	if outCount := uint(coutCount); outCount > 0 {
		attributes = make([]PropertyAttribute, outCount)

		for i, elem := uint(0), attrList; i < outCount; i++ {
			attributes[i] = makePropertyAttribute(*elem)
			elem = nextPropertyAttr(elem)
		}
	}

	return
}

func nextProperty(list *C.objc_property_t) *C.objc_property_t {
	ptr := uintptr(unsafe.Pointer(list)) + unsafe.Sizeof(*list)
	return (*C.objc_property_t)(unsafe.Pointer(ptr))
}

func nextPropertyAttr(list *C.objc_property_attribute_t) *C.objc_property_attribute_t {
	ptr := uintptr(unsafe.Pointer(list)) + unsafe.Sizeof(*list)
	return (*C.objc_property_attribute_t)(unsafe.Pointer(ptr))
}
