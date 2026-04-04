//go:build !unix

package dyld

import (
	"fmt"
	"io"
	"os"
)

func a2sMmap(f *os.File, size int) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("a2s: nil file")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(f, 0, int64(size)), data); err != nil {
		return nil, fmt.Errorf("a2s: failed to read file: %w", err)
	}
	return data, nil
}

func a2sMunmap(data []byte) error {
	return nil // no-op: data is a regular slice, GC handles it
}
