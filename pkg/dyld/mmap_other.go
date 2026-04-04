//go:build !unix

package dyld

import (
	"io"
	"os"
)

func openCacheFile(name string) (io.ReaderAt, io.Closer, int64, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, 0, err
	}
	return f, f, fi.Size(), nil
}
