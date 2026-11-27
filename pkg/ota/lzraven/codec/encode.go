package codec

/*
#include "upstream/lzraven.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// EncodeBound returns the maximum encoded size supported by the codec.
func EncodeBound(size int) (int, error) {
	if size < 0 {
		return 0, fmt.Errorf("lzraven: negative input size")
	}
	bound := uint64(C.lzraven_encode_bound(C.size_t(size)))
	if bound == 0 || bound > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("lzraven: unsupported input size %d", size)
	}
	return int(bound), nil
}

// Encode compresses src into a newly allocated LZRaven frame.
func Encode(src []byte) ([]byte, error) {
	bound, err := EncodeBound(len(src))
	if err != nil {
		return nil, err
	}
	dst := make([]byte, bound)
	n := C.lzraven_encode_buffer(unsafe.Pointer(unsafe.SliceData(dst)), C.size_t(len(dst)),
		unsafe.Pointer(unsafe.SliceData(src)), C.size_t(len(src)))
	if n == 0 || uint64(n) > uint64(len(dst)) {
		return nil, fmt.Errorf("lzraven: encoding failed")
	}
	return dst[:int(n)], nil
}
