//go:build cgo

package sep

/*
#cgo LDFLAGS: ./lib/libsepsplit_rs.a -ldl
#include <stdlib.h>

int split(const char* filein, const char* outdir);
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

func Split(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	input := C.CString(src)
	defer C.free(unsafe.Pointer(input))

	output := C.CString(dst)
	defer C.free(unsafe.Pointer(output))

	if C.split(input, output) != 0 {
		return fmt.Errorf("failed to split %s", src)
	}

	return nil
}
