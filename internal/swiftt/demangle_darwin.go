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
        return -1;
    }
    if (output == NULL) {
        fprintf(stderr, "output string is NULL\n");
        return -1;
    }

    void *handle = dlopen("/Applications/Xcode.app/Contents/Frameworks/libswiftDemangle.dylib", RTLD_LAZY);
    if (!handle) {
        handle = dlopen("/Library/Developer/CommandLineTools/usr/lib/libswiftDemangle.dylib", RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            return -1;
        }
    }

    swift_demangle_getDemangledName *swift_demangle_getDemangledName = dlsym(handle, "swift_demangle_getDemangledName");
    if (!swift_demangle_getDemangledName) {
        fprintf(stderr, "%s\n", dlerror());
        return -1;
    }

    swift_demangle_getDemangledName(input, output, length);

    if (dlclose(handle) != 0) {
        fprintf(stderr, "dlclose failed: %s\n", dlerror());
        return -1;
    }

    return 0;
}

int SwiftDemangleSimple(char *input, char *output, size_t length) {
    if (input == NULL || input[0] == '\0') {
        fprintf(stderr, "input string is NULL\n");
        return -1;
    }
    if (output == NULL) {
        fprintf(stderr, "output string is NULL\n");
        return -1;
    }

    void *handle = dlopen("/Applications/Xcode.app/Contents/Frameworks/libswiftDemangle.dylib2", RTLD_LAZY);
    if (!handle) {
        handle = dlopen("/Library/Developer/CommandLineTools/usr/lib/libswiftDemangle.dylib", RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "%s\n", dlerror());
            return -1;
        }
    }

    swift_demangle_getSimplifiedDemangledName *swift_demangle_getSimplifiedDemangledName = dlsym(handle, "swift_demangle_getSimplifiedDemangledName");
    if (!swift_demangle_getSimplifiedDemangledName) {
        fprintf(stderr, "%s\n", dlerror());
        return -1;
    }

    swift_demangle_getSimplifiedDemangledName(input, output, length);

    if (dlclose(handle) != 0) {
        fprintf(stderr, "dlclose failed: %s\n", dlerror());
        return -1;
    }

    return 0;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

func Demangle(input string) (string, error) {
	output := (*C.char)(C.malloc(2048))
	defer C.free(unsafe.Pointer(output))

	i := C.CString(input)
	defer C.free(unsafe.Pointer(i))

	if ret := C.SwiftDemangle(i, output, C.size_t(2048)); ret != 0 {
		return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New(C.GoString(C.dlerror())))
	}

	return C.GoString(output), nil
}

func DemangleSimple(input string) (string, error) {
	output := (*C.char)(C.malloc(2048))
	defer C.free(unsafe.Pointer(output))

	i := C.CString(input)
	defer func() { C.free(unsafe.Pointer(i)) }()

	if ret := C.SwiftDemangleSimple(i, output, C.size_t(2048)); ret != 0 {
		return "", fmt.Errorf("error parsing mangled symbol: %v", errors.New(C.GoString(C.dlerror())))
	}

	return C.GoString(output), nil
}
