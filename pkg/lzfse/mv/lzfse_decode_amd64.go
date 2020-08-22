//+build !noasm
//+build !appengine

package lzfse

import (
	"unsafe"
)

//go:noescape
func __lzfse_decode_scratch_size(result uint64)

//go:noescape
func __lzfse_decode_buffer(dstBuffer unsafe.Pointer, dstSize uint64, srcBuffer unsafe.Pointer, srcSize uint64, scratchBuffer unsafe.Pointer)

//go:noescape
func __lzfse_decode_buffer_with_scratch(dstBuffer unsafe.Pointer, dstSize uint64, srcBuffer unsafe.Pointer, srcSize uint64, scratchBuffer unsafe.Pointer)

func lzfse_decode_scratch_size() uint64 {
	var result uint64
	__lzfse_decode_scratch_size(result)
	return result
}

func DecodeBuffer(srcBuffer []byte) []byte {

	dstBuffer := make([]byte, 4*len(srcBuffer))
	scratchBuffer := make([]byte, lzfse_decode_scratch_size())
	__lzfse_decode_buffer(unsafe.Pointer(&dstBuffer), uint64(len(dstBuffer)), unsafe.Pointer(&dstBuffer), uint64(len(dstBuffer)), unsafe.Pointer(&scratchBuffer))

	return dstBuffer
}
