package codec

/*
#cgo CFLAGS: -std=c11
#include "upstream/lzraven.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// Decode fills dst with the decoded stream. The caller supplies its exact size.
// Each buffer is limited to 2^32-1 bytes per call by the imported codec.
// The buffers must not overlap. On failure, dst may be partially written.
// Decode stops at the first terminator, ignoring trailing bytes.
func Decode(dst, src []byte) error {
	if uint64(len(src)) > 0xffffffff || uint64(len(dst)) > 0xffffffff {
		return fmt.Errorf("lzraven: buffer exceeds the codec's per-call 32-bit size limit")
	}
	if len(src) < 12 || binary.LittleEndian.Uint32(src) != 0xecca002b ||
		binary.LittleEndian.Uint32(src[4:])&0x03ffffff != 0 {
		return fmt.Errorf("lzraven: invalid stream header")
	}
	// The codec returns zero both for an empty frame and for a decoding
	// failure. A first-block terminator identifies the valid empty case
	// unambiguously.
	if len(dst) == 0 {
		if binary.LittleEndian.Uint32(src[8:])>>12 == 0 {
			return nil
		}
		return fmt.Errorf("lzraven: nonempty stream requires output space")
	}
	n := C.lzraven_decode_buffer(unsafe.Pointer(unsafe.SliceData(dst)), C.size_t(len(dst)),
		unsafe.Pointer(unsafe.SliceData(src)), C.size_t(len(src)))
	if uint64(n) != uint64(len(dst)) {
		return fmt.Errorf(
			"lzraven: decode returned %d bytes, expected %d",
			uint64(n),
			len(dst),
		)
	}
	return nil
}
