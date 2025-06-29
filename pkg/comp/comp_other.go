//go:build !darwin

package comp

import (
	"fmt"

	"github.com/blacktop/lzfse-cgo"
)

// compress compresses the given data using the specified algorithm.
func compress(data []byte, algorithm Algorithm) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data is empty")
	}

	// Fallback to lzfse-cgo for LZFSE on other platforms
	if algorithm == LZFSE || algorithm == LZFSE_IBOOT {
		compressedData := lzfse.EncodeBuffer(data)
		if len(compressedData) == 0 {
			return nil, fmt.Errorf("failed to LZFSE compress data")
		}
		return compressedData, nil
	}
	return nil, fmt.Errorf("compression algorithm not supported on this platform")
}

// decompress decompresses the given data using the specified algorithm.
func decompress(data []byte, algorithm Algorithm) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data is empty")
	}

	// Fallback to lzfse-cgo for LZFSE on other platforms
	if algorithm == LZFSE || algorithm == LZFSE_IBOOT {
		decompressedData := lzfse.DecodeBuffer(data)
		if len(decompressedData) == 0 {
			return nil, fmt.Errorf("failed to LZFSE decompress data")
		}
		return decompressedData, nil
	}
	return nil, fmt.Errorf("decompression algorithm not supported on this platform")
}
