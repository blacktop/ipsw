package aea

import (
	"sync"

	"github.com/blacktop/lzfse-cgo"
)

// scratchPool holds scratch buffers for lzfse decoding.
// Each buffer is sized to lzfse.DecodeScratchSize() bytes.
var scratchPool = sync.Pool{
	New: func() any {
		buf := make([]byte, lzfse.DecodeScratchSize())
		return &buf
	},
}

// decodeLZFSE decodes LZFSE compressed data into a pre-allocated destination buffer.
// Uses lzfse.DecodeBufferWithScratch with pooled scratch buffers for optimal performance.
//
// Returns the number of bytes written to dst, or 0 on failure.
func decodeLZFSE(src, dst []byte) int {
	if len(src) == 0 || len(dst) == 0 {
		return 0
	}
	// Get scratch buffer from pool
	scratchPtr := scratchPool.Get().(*[]byte)
	defer scratchPool.Put(scratchPtr)

	return lzfse.DecodeBufferWithScratch(src, dst, *scratchPtr)
}
