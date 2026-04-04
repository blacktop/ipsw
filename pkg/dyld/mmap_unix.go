//go:build unix

package dyld

import (
	"io"
	"os"
	"syscall"
)

type mmapReaderAt struct {
	data []byte
}

func (m *mmapReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *mmapReaderAt) Close() error {
	return syscall.Munmap(m.data)
}

func openCacheFile(name string) (io.ReaderAt, io.Closer, int64, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, 0, err
	}
	size := fi.Size()
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, 0, err
	}
	mr := &mmapReaderAt{data: data}
	return mr, mr, size, nil
}
