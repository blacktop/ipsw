//go:build darwin && cgo

package ridiff

/*
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef struct
{
    int64_t unknown1;
    int64_t unknown2;
    char *input;
    char *output;
    char *patch;
    uint32_t not_cryptex_cache;
    uint32_t threads; // 0 means use all hw.physicalcpu
    uint32_t verbose;
} RawImage;

typedef int64_t RawImagePatch(RawImage *);

int ParseRawImage(char *output, char *patch);

int ParseRawImage(char *output, char *patch) {
	void *handle = dlopen("/usr/lib/libParallelCompression.dylib", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		return 1;
	}

	RawImagePatch *RawImagePatch = dlsym(handle, "RawImagePatch");
	if (!RawImagePatch) {
		fprintf(stderr, "%s\n", dlerror());
		return 1;
	}

    RawImage ri = {
        .unknown1 = 0,
        .unknown2 = 0,
        .input = NULL,
        .output = output,
        .patch = patch,
        .not_cryptex_cache = 0,
        .threads = 0,
        .verbose = 0,
    };

	int64_t ret = RawImagePatch(&ri);
	if (ret != 0) {
		fprintf(stderr, "RawImagePatch returned %lld", ret);
		return ret;
	}

	if (dlclose(handle) != 0) {
		fprintf(stderr, "dlclose failed: %s\n", dlerror());
		return 1;
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

// RawImagePatch takes a Raw Image Diff and converts it to an APFS volume.
func RawImagePatch(patch, output string) error {

	p := C.CString(patch)
	defer C.free(unsafe.Pointer(p))

	o := C.CString(output)
	defer C.free(unsafe.Pointer(o))

	ret := C.ParseRawImage(o, p)
	if ret != 0 {
		return fmt.Errorf("error parsing raw image: %v", errors.New(C.GoString(C.dlerror())))
	}

	return nil
}
