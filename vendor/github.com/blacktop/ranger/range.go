package ranger

// RangeFetcher is the interface that wraps the FetchBlocks method.
//
// FetchBlocks fetches the specified block ranges and returns any errors encountered in doing so.
//
// Length returns the length, in bytes, of the ranged-over source.
//
// Initialize, called once and passed the Reader's block size, performs any necessary setup tasks for the RangeFetcher
type RangeFetcher interface {
	FetchRanges([]ByteRange) ([]Block, error)
	ExpectedLength() (int64, error)
}

// Block represents a block returned from a ranged read
type Block struct {
	Length int64
	Data   []byte
}

// ByteRange represents a not-yet-fetched range of bytes
type ByteRange struct {
	Start, End int64
}

// blockRange returns the starting block and number of full blocks covered by a byte range at the given block size
func blockRange(off int64, length int, blockSize int) (int, int) {
	startBlock := int(off / int64(blockSize))
	endBlock := int((off + int64(length)) / int64(blockSize))
	endBlockOff := (off + int64(length)) % int64(blockSize)
	nblocks := endBlock - startBlock
	if endBlockOff > 0 {
		nblocks++
	}
	return startBlock, nblocks
}

// coalesceAdjacentRanges coalesces ranges that are directly adjacent
func coalesceAdjacentRanges(ranges []ByteRange) []ByteRange {
	out := make([]ByteRange, 0, len(ranges))
	ls, le := int64(-1), int64(-1)
	for i := range ranges {
		r := &ranges[i]
		if ls != -1 && r.Start != le+1 {
			// this range is different; vend the last one
			out = append(out, ByteRange{ls, le})
			ls = -1
		}

		if ls == -1 {
			// not yet seen a range
			ls, le = r.Start, r.End
		} else if r.Start == le+1 {
			// this range is contiguous with the last
			le = r.End
		}
	}
	if ls != -1 {
		out = append(out, ByteRange{ls, le})
	}
	return out
}
