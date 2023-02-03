//go:build darwin && cgo && objc

package objc

/*
#include <stdlib.h>
#include <objc/runtime.h>

static int objcBOOL2int(BOOL b) {
	return (int)b;
}
*/
import "C"
import "unsafe"

type Protocol uintptr

func (p Protocol) cprot() *C.Protocol {
	return (*C.Protocol)(unsafe.Pointer(p))
}

func GetProtocol(name string) Protocol {
	return (Protocol)(unsafe.Pointer(C.objc_getProtocol(C.CString(name))))
}

func GetProtocols() (protocols []Protocol) {
	var coutCount C.uint

	protocolList := C.objc_copyProtocolList(&coutCount)
	defer C.free(unsafe.Pointer(protocolList))

	if outCount := uint(coutCount); outCount > 0 {
		protocols = make([]Protocol, outCount)

		for i, elem := uint(0), protocolList; i < outCount; i++ {
			protocols[i] = (Protocol)(unsafe.Pointer((*elem)))
			elem = nextProtocol(elem)
		}
	}

	return
}

func (p Protocol) Name() string {
	return C.GoString(C.protocol_getName(p.cprot()))
}

// func (p Protocol) AddMethodDescription(name Sel, types string, isRequiredMethod bool, isInstanceMethod bool) {
// 	ctypes := C.CString(types)
// 	defer C.free(unsafe.Pointer(ctypes))

// 	C.protocol_addMethodDescription(p.cprot(), name.csel(), ctypes, C.BOOL(isRequiredMethod), C.BOOL(isInstanceMethod))
// }

func (p Protocol) AddProtocol(addition Protocol) {
	C.protocol_addProtocol(p.cprot(), addition.cprot())
}

// func (p Protocol) AddProperty(name string, attributes []PropertyAttribute, isRequiredProperty bool, isInstanceProperty bool) {
// 	var cattributes *C.objc_property_attribute_t

// 	cname := C.CString(name)
// 	defer C.free(unsafe.Pointer(cname))

// 	attrSize := unsafe.Sizeof(*cattributes)
// 	attributeCount := len(attributes)

// 	if len(attributes) != 0 {
// 		cattributes = (*C.objc_property_attribute_t)(C.calloc(C.size_t(attributeCount), C.size_t(attrSize)))

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

// 	C.protocol_addProperty(p.cprot(), cname, cattributes, C.uint(attributeCount), C.BOOL(isRequiredProperty), C.BOOL(isInstanceProperty))
// }

// func (p Protocol) CopyMethodDescriptionList(isRequiredMethod bool, isInstanceMethod bool) (descriptions []MethodDescription) {
// 	var coutCount C.uint

// 	descriptionList := C.protocol_copyMethodDescriptionList(p.cprot(), C.BOOL(isRequiredMethod), C.BOOL(isInstanceMethod), &coutCount)
// 	defer C.free(unsafe.Pointer(descriptionList))

// 	if outCount := uint(coutCount); outCount > 0 {
// 		descriptions = make([]MethodDescription, outCount)

// 		for i, elem := uint(0), descriptionList; i < outCount; i++ {
// 			descriptions[i] = makeMethodDescription(*elem)
// 			elem = nextMethodDescription(elem)
// 		}
// 	}

// 	return
// }

// func (p Protocol) MethodDescription(aSel Sel, isRequiredMethod bool, isInstanceMethod bool) MethodDescription {
// 	cmethodDescription := C.protocol_getMethodDescription(p.cprot(), aSel.csel(), C.BOOL(isRequiredMethod), C.BOOL(isInstanceMethod))
// 	return makeMethodDescription(cmethodDescription)
// }

func (p Protocol) CopyPropertyList() (properties []Property) {
	var coutCount C.uint

	propertyList := C.protocol_copyPropertyList(p.cprot(), &coutCount)
	defer C.free(unsafe.Pointer(propertyList))

	if outCount := uintptr(coutCount); outCount > 0 {
		properties = make([]Property, outCount)

		for i, elem := uintptr(0), propertyList; i < outCount; i++ {
			properties[i] = (Property)(unsafe.Pointer((*elem)))
			elem = nextProperty(elem)
		}
	}

	return
}

// func (p Protocol) Property(name string, isRequiredProperty bool, isInstanceProperty bool) Property {
// 	cname := C.CString(name)
// 	defer C.free(unsafe.Pointer(cname))

// 	return (Property)(unsafe.Pointer(C.protocol_getProperty(p.cprot(), cname, C.BOOL(isRequiredProperty), C.BOOL(isInstanceProperty))))
// }

func (p Protocol) CopyProtocolList() (protocols []Protocol) {
	var coutCount C.uint

	protocolList := C.protocol_copyProtocolList(p.cprot(), &coutCount)
	defer C.free(unsafe.Pointer(protocolList))

	if outCount := uint(coutCount); outCount > 0 {
		protocols = make([]Protocol, outCount)

		for i, elem := uint(0), protocolList; i < outCount; i++ {
			protocols[i] = (Protocol)(unsafe.Pointer((*elem)))
			elem = nextProtocol(elem)
		}
	}

	return
}

func (p Protocol) ConformsToProtocol(other Protocol) bool {
	return C.objcBOOL2int(C.protocol_conformsToProtocol(p.cprot(), other.cprot())) != 0
}

func nextProtocol(list **C.Protocol) **C.Protocol {
	ptr := uintptr(unsafe.Pointer(list)) + unsafe.Sizeof(*list)
	return (**C.Protocol)(unsafe.Pointer(ptr))
}
