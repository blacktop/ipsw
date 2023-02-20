//go:build darwin && cgo

package swift

/*
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef size_t swift_demangle_getDemangledName(const char *MangledName, char *OutputBuffer, size_t Length);
typedef size_t swift_demangle_getSimplifiedDemangledName(const char *MangledName, char *OutputBuffer, size_t Length);

int SwiftDemangle(char *input, char *output, size_t length);
int SwiftDemangleSimple(char *input, char *output, size_t length);

int SwiftDemangle(char *input, char *output, size_t length) {
    if (input == NULL || input[0] == '\0') {
        fprintf(stderr, "input string is NULL\n");
        return -3;
    }
    if (output == NULL) {
        fprintf(stderr, "output string is NULL\n");
        return -3;
    }

    void *handle = dlopen("/usr/lib/swift/libswiftDemangle.dylib", RTLD_LAZY);
    if (!handle) {
        return -2;
    }

    swift_demangle_getDemangledName *swift_demangle_getDemangledName = dlsym(handle, "swift_demangle_getDemangledName");
    if (!swift_demangle_getDemangledName) {
        return -1;
    }

    size_t ret = swift_demangle_getDemangledName(input, output, length);

    if (dlclose(handle) != 0) {
        return -1;
    }

    return ret;
}

int SwiftDemangleSimple(char *input, char *output, size_t length) {
    if (input == NULL || input[0] == '\0') {
        fprintf(stderr, "input string is NULL\n");
        return -3;
    }
    if (output == NULL) {
        fprintf(stderr, "output string is NULL\n");
        return -3;
    }

    void *handle = dlopen("/usr/lib/swift/libswiftDemangle.dylib", RTLD_LAZY);
    if (!handle) {
        return -2;
    }

    swift_demangle_getSimplifiedDemangledName *swift_demangle_getSimplifiedDemangledName = dlsym(handle, "swift_demangle_getSimplifiedDemangledName");
    if (!swift_demangle_getSimplifiedDemangledName) {
        return -1;
    }

    size_t ret = swift_demangle_getSimplifiedDemangledName(input, output, length);

    if (dlclose(handle) != 0) {
        return -1;
    }

    return ret;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"regexp"
	"unsafe"
)

type errType int

const (
	NOOP    = 0
	ERROR   = -1
	NODYLIB = -2
	BADARGS = -3
)

func Demangle(input string) (string, error) {
	output := (*C.char)(C.malloc(2048))
	defer C.free(unsafe.Pointer(output))

	i := C.CString(input)
	defer C.free(unsafe.Pointer(i))

	if ret := C.SwiftDemangle(i, output, C.size_t(2048)); ret <= NOOP {
		switch ret {
		case BADARGS:
			return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New("bad arguments (one or more arguments are NULL)"))
		case NODYLIB:
			return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New("libswiftDemangle.dylib not found"))
		case NOOP:
			return input, nil
		case ERROR:
			fallthrough
		default:
			return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New(C.GoString(C.dlerror())))
		}
	}

	return C.GoString(output), nil
}

func DemangleBlob(blob string) string {
	words := regexp.MustCompile(`\b(_\$s)?\w+\b`)
	blob = words.ReplaceAllStringFunc(blob, func(s string) string {
		out, err := Demangle(s)
		if err != nil {
			return s
		}
		return out
	})
	return blob
}

func DemangleSimple(input string) (string, error) {
	output := (*C.char)(C.malloc(2048))
	defer C.free(unsafe.Pointer(output))

	i := C.CString(input)
	defer func() { C.free(unsafe.Pointer(i)) }()

	if ret := C.SwiftDemangleSimple(i, output, C.size_t(2048)); ret <= NOOP {
		switch ret {
		case BADARGS:
			return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New("bad arguments (one or more arguments are NULL)"))
		case NODYLIB:
			return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New("libswiftDemangle.dylib not found"))
		case NOOP:
			return input, nil
		case ERROR:
			fallthrough
		default:
			return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New(C.GoString(C.dlerror())))
		}
	}

	return C.GoString(output), nil
}

func DemangleSimpleBlob(blob string) string {
	words := regexp.MustCompile(`\b(_\$s)?\w+\b`)
	blob = words.ReplaceAllStringFunc(blob, func(s string) string {
		out, err := DemangleSimple(s)
		if err != nil {
			return s
		}
		return out
	})
	return blob
}
