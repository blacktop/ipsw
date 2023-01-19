//go:build cgo

package sep

/*
#cgo LDFLAGS: ${SRCDIR}/lib/libsepsplit_rs.a -ldl
#include <stdlib.h>

int split(const char* filein, const char* outdir, unsigned int verbose);
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"unsafe"
)

func Split(src, dst string) error {

	if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("file %s does not exist", src)
	}

	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	input := C.CString(src)
	defer C.free(unsafe.Pointer(input))

	output := C.CString(dst)
	defer C.free(unsafe.Pointer(output))

	if C.split(input, output, 0) != 0 {
		return fmt.Errorf("failed to split %s", src)
	}

	return nil
}
