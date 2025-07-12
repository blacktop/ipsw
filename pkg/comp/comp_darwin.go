//go:build darwin && cgo

package comp

/*
#cgo LDFLAGS: -L/usr/lib -lcompression
#include <compression.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// compress compresses the given data using the specified algorithm.
func compress(data []byte, algorithm Algorithm) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data is empty")
	}

	destBuf := make([]byte, len(data)+256) // Allocate a buffer large enough for compressed data

	size := C.compression_encode_buffer(
		(*C.uint8_t)(unsafe.Pointer(&destBuf[0])),
		C.size_t(len(destBuf)),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		nil,
		C.compression_algorithm(algorithm),
	)

	if size == 0 {
		return nil, fmt.Errorf("failed to compress data")
	}

	return destBuf[:size], nil
}

// decompress decompresses the given data using the specified algorithm.
func decompress(data []byte, algorithm Algorithm) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data is empty")
	}

	// Start with a reasonable buffer size, and grow if needed
	decmpSize := max(len(data)*2, 4096)

	for {
		destBuf := make([]byte, decmpSize)

		size := C.compression_decode_buffer(
			(*C.uint8_t)(unsafe.Pointer(&destBuf[0])),
			C.size_t(decmpSize),
			(*C.uint8_t)(unsafe.Pointer(&data[0])),
			C.size_t(len(data)),
			nil,
			C.compression_algorithm(algorithm),
		)

		if size == 0 {
			return nil, fmt.Errorf("failed to decompress data")
		}

		if size == C.size_t(decmpSize) {
			// Buffer was too small, double it and try again
			decmpSize *= 2
			continue
		}

		return destBuf[:size], nil
	}
}
