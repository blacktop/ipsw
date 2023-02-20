package dyld

import (
	"io"

	"github.com/blacktop/go-macho/types"
	"github.com/pkg/errors"
)

// Seek whence values.
const (
	SeekStart   = 0 // seek relative to the origin of the file
	SeekCurrent = 1 // seek relative to the current offset
	SeekEnd     = 2 // seek relative to the end
)

var EOF = errors.New("EOF")

type DyldSharedCacheReader struct {
	base  int64
	off   int64
	limit int64

	cache *File
	ruuid types.UUID
}

// TODO: 🚧 finish this and replace all the other readers with it
func NewDyldSharedCacheReader(f *File, off int64) *DyldSharedCacheReader {
	return &DyldSharedCacheReader{
		base:  off,
		off:   off,
		limit: f.size,
		cache: f,
	}
}

func (cr *DyldSharedCacheReader) Seek(offset int64, whence int) (n int64, err error) {
	switch whence {
	default:
		return 0, errors.New("Seek: invalid whence")
	case SeekStart:
		offset += cr.base
	case SeekCurrent:
		offset += cr.off
	case SeekEnd:
		offset += cr.limit
	}
	if offset < cr.base {
		return 0, errors.New("Seek: invalid offset")
	}
	cr.off = offset
	cr.ruuid, _, err = cr.cache.GetCacheVMAddress(uint64(offset))
	if err != nil {
		return 0, err
	}
	return offset - cr.base, nil
}

func (cr *DyldSharedCacheReader) SeekToAddr(addr uint64) error {
	uuid, offset, err := cr.cache.GetOffset(addr)
	if err != nil {
		return err
	}
	cr.ruuid = uuid
	_, err = cr.Seek(int64(offset), io.SeekStart)
	return err
}

func (cr *DyldSharedCacheReader) Read(p []byte) (n int, err error) {
	if cr.off >= cr.limit {
		return 0, EOF
	}
	if max := cr.limit - cr.off; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err = cr.ReadAt(p, cr.off)
	cr.off += int64(n)
	return
}

func (cr *DyldSharedCacheReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= cr.limit-cr.base {
		return 0, EOF
	}
	off += cr.base
	if max := cr.limit - off; int64(len(p)) > max {
		p = p[0:max]
		n, err = cr.ReadAt(p, off)
		if err == nil {
			err = EOF
		}
		return n, err
	}
	return cr.cache.r[cr.ruuid].ReadAt(p, off)
}

// ReadAtAddr reads data at a given virtual address
func (cr *DyldSharedCacheReader) ReadAtAddr(buf []byte, addr uint64) (int, error) {
	uuid, off, err := cr.cache.GetOffset(addr)
	if err != nil {
		return -1, err
	}
	cr.ruuid = uuid
	return cr.cache.r[cr.ruuid].ReadAt(buf, int64(off))
}

// Size returns the size of the section in bytes.
func (cr *DyldSharedCacheReader) Size() int64 { return cr.limit - cr.base }
