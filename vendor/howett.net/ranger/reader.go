package ranger

import (
	"errors"
	"io"
	"sync"
)

// DefaultBlockSize is the default size for the blocks that are downloaded from the server and cached.
const DefaultBlockSize int = 128 * 1024

// Reader is an io.ReaderAt and io.ReadSeeker backed by a partial block store.
type Reader struct {
	// the range fetcher with which to download blocks
	Fetcher RangeFetcher

	// size of the blocks fetched from the source and cached; lower values translate to lower memory usage, but typically require more requests
	BlockSize int

	once sync.Once
	len  int64 // protected by once

	mutex  sync.RWMutex
	off    int64
	blocks map[int][]byte
}

// ReadAt reads len(p) bytes from the ranged-over source.
// It returns the number of bytes read and the error, if any.
// ReadAt always returns a non-nil error when n < len(b). At end of file, that error is io.EOF.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	err := r.init()
	if err != nil {
		return 0, err
	}

	l := len(p)

	if off < 0 {
		return 0, errors.New("read before beginning of file")
	}

	if off+int64(l) > r.len {
		l = int(r.len - off)
	}

	if off >= r.len {
		return 0, errors.New("read beyond end of file")
	}

	// Lock here so that we don't end up dispatching
	// multiple requests for the same blocks.
	r.mutex.Lock()

	startBlock, nblocks := blockRange(off, l, r.BlockSize)
	blockNumbers := make([]int, nblocks)
	ranges := make([]ByteRange, nblocks)
	nreq := 0
	for i := 0; i < nblocks; i++ {
		bn := startBlock + i
		if _, ok := r.blocks[bn]; ok {
			continue
		}
		blockNumbers[nreq] = bn
		ranges[nreq] = ByteRange{
			int64(bn * r.BlockSize),
			int64(((bn + 1) * r.BlockSize) - 1),
		}
		if ranges[nreq].End > r.len {
			ranges[nreq].End = r.len
		}

		nreq++
	}

	ranges = ranges[:nreq]

	blox, err := r.Fetcher.FetchRanges(ranges)
	if err != nil {
		r.mutex.Unlock()
		return 0, err
	}
	for i, v := range blox {
		r.blocks[blockNumbers[i]] = v.Data
	}

	r.mutex.Unlock()

	return r.copyRangeToBuffer(p[:l], off)
}

// invariant: after init(); p is appropriately sized
func (r *Reader) copyRangeToBuffer(p []byte, off int64) (int, error) {
	remaining := len(p)
	block := int(off / int64(r.BlockSize))
	startOffset := off % int64(r.BlockSize)
	ncopied := 0

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for remaining > 0 {
		copylen := r.BlockSize
		if copylen > remaining {
			copylen = remaining
		}

		// if we need to copy more bytes than exist in this block
		if startOffset+int64(copylen) > int64(r.BlockSize) {
			copylen = int(int64(r.BlockSize) - startOffset)
		}

		if _, ok := r.blocks[block]; !ok {
			return 0, errors.New("lies: we were told we had blocks to copy")
		}
		copy(p[ncopied:ncopied+copylen], r.blocks[block][startOffset:])

		remaining -= copylen
		ncopied += copylen

		block++
		startOffset = 0
	}

	var err error
	if off+int64(len(p)) == r.len {
		err = io.EOF
	}

	return ncopied, err
}

// Length returns the length of the ranged-over source.
func (r *Reader) Length() (int64, error) {
	err := r.init()
	if err != nil {
		return 0, err
	}
	return r.len, nil
}

// Read reads len(p) bytes from ranged-over source.
// It returns the number of bytes read and the error, if any.
// EOF is signaled by a zero count with err set to io.EOF.
func (r *Reader) Read(p []byte) (int, error) {
	err := r.init()
	if err != nil {
		return 0, err
	}

	if r.off == r.len {
		return 0, io.EOF
	}

	nread, err := r.ReadAt(p, r.off)
	r.off += int64(nread)
	return nread, err
}

// Seek sets the offset for the next Read to offset, interpreted
// according to whence: 0 means relative to the origin of the file, 1 means relative
// to the current offset, and 2 means relative to the end. It returns the new offset
// and an error, if any.
func (r *Reader) Seek(off int64, whence int) (int64, error) {
	err := r.init()
	if err != nil {
		return 0, err
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	switch whence {
	case 0: // set
		r.off = off
	case 1: // cur
		off = r.off + off
	case 2: // end
		off = r.len + off
	}

	if off > r.len {
		return 0, errors.New("seek beyond end of file")
	}

	if off < 0 {
		return 0, errors.New("seek before beginning of file")
	}

	r.off = off
	return r.off, nil
}

func (r *Reader) init() (err error) {
	r.once.Do(func() {
		r.blocks = make(map[int][]byte)
		if r.BlockSize == 0 {
			r.BlockSize = DefaultBlockSize
		}

		r.len, err = r.Fetcher.ExpectedLength()
	})
	return
}

// NewReader returns a newly-initialized Reader,
// which also initializes its provided RangeFetcher.
// It returns the new reader and an error, if any.
func NewReader(fetcher RangeFetcher) (*Reader, error) {
	r := &Reader{
		Fetcher: fetcher,
	}
	err := r.init()
	if err != nil {
		return nil, err
	}
	return r, nil
}
