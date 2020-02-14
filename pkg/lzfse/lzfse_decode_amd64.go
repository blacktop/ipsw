//+build !noasm
//+build !appengine

package lzfse

import (
	"unsafe"
)

//go:noescape
func _lzfse_decode_scratch_size() uint32

//go:noescape
func _lzfse_decode_buffer(dstBuffer unsafe.Pointer, dstSize uint64, srcBuffer unsafe.Pointer, srcSize uint64, scratchBuffer unsafe.Pointer)

//go:noescape
func _lzfse_decode_buffer_with_scratch(dstBuffer unsafe.Pointer, dstSize uint64, srcBuffer unsafe.Pointer, srcSize uint64, scratchBuffer unsafe.Pointer)

func lzfse_decode_scratch_size() uint32 {
	return _lzfse_decode_scratch_size()
}

func lzfse_decode_buffer(srcBuffer []byte) []byte {

	dstBuffer := make([]byte, 4*len(srcBuffer))
	scratchBuffer := make([]byte, lzfse_decode_scratch_size())
	_lzfse_decode_buffer(unsafe.Pointer(&dstBuffer), uint64(len(dstBuffer)), unsafe.Pointer(&dstBuffer), uint64(len(dstBuffer)), unsafe.Pointer(&scratchBuffer))

	return dstBuffer
}
