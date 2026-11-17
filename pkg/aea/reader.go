package aea

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Reader authenticates cluster metadata and decrypts only requested AEA segments.
// It does not verify unread payloads, archive padding, or an external APFS seal.
// Concurrent reads are serialized. The plaintext cache holds 32 MiB of
// segments, and always at least one, so a larger segment exceeds that.
type Reader struct {
	mu       sync.Mutex
	source   io.ReaderAt
	root     RootHeader
	segments []decryptSegment
	cache    *lru.Cache[int, []byte]
	decoder  segmentDecoder
}

func (r *Reader) Size() int64 { return int64(r.root.FileSize) }

// maxIndexedSegments bounds the in-memory segment index.
const maxIndexedSegments = 1 << 20

// NewReader opens an AEA1 symmetric archive over a seekable source. Call
// ReadMetadata and Metadata.SymmetricKey to resolve a public restore-image key.
func NewReader(source io.ReaderAt, size int64, key []byte) (*Reader, error) {
	mainKey, root, clusterMAC, offset, err := readPrologue(source, size, key)
	if err != nil {
		return nil, err
	}
	checksumBytes, err := validateRoot(root, size)
	if err != nil {
		return nil, err
	}
	if (root.FileSize+uint64(root.SegmentSize)-1)/uint64(root.SegmentSize) > maxIndexedSegments {
		return nil, fmt.Errorf("AEA segment index exceeds limit")
	}
	r := &Reader{source: source, root: root}
	r.cache, err = lru.New[int, []byte](max(1, decryptMemoryBudget/int(root.SegmentSize)))
	if err != nil {
		return nil, err
	}
	// Header HMACs form a chain, so index every cluster header in order; no
	// segment data is read during indexing.
	_, _, err = walkSegments(context.Background(), source, offset, size, mainKey, clusterMAC, root, checksumBytes, func(job decryptSegment) error {
		r.segments = append(r.segments, job)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if off < 0 {
		return 0, fmt.Errorf("negative AEA offset")
	}
	n := 0
	for n < len(p) && off < r.Size() {
		index := int(off / int64(r.root.SegmentSize))
		job := r.segments[index]
		data, ok := r.cache.Get(index)
		if !ok {
			decoded, err := r.decoder.decrypt(r.source, job, r.root.Compression, r.root.Checksum)
			if err != nil {
				return n, err
			}
			data = bytes.Clone(decoded)
			r.cache.Add(index, data)
		}
		count := copy(p[n:], data[off-job.output:])
		n += count
		off += int64(count)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
