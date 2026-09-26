package dyld

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

// slideReadTracker records reads under a lock so the race test also exercises
// cold, concurrent metadata initialization, rather than just a warmed cache.
type slideReadTracker struct {
	mu             sync.Mutex
	data           []byte
	metadataBytes  int
	pointerOffsets []int64
}

func (r *slideReadTracker) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if off < 0x1000 {
		r.metadataBytes += len(p)
	} else {
		r.pointerOffsets = append(r.pointerOffsets, off)
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}

func slideCacheFixture(t *testing.T, version uint32) (*File, *CacheMappingWithSlideInfo, *slideReadTracker, int) {
	t.Helper()
	var header any
	starts := []uint16{0xffff, 0x18}
	var extras []uint16
	switch version {
	case 1:
		header = CacheSlideInfo{Version: 1, TocOffset: 24, TocCount: 2, EntriesOffset: 28, EntriesCount: 1, EntriesSize: 0}
		starts = []uint16{0, 0}
	case 2:
		header = CacheSlideInfo2{Version: 2, PageSize: 0x1000, PageStartsOffset: 40, PageStartsCount: 2, PageExtrasOffset: 44, PageExtrasCount: 1, DeltaMask: 0xc000000000000000}
		starts = []uint16{DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE, DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA}
		extras = []uint16{DYLD_CACHE_SLIDE_PAGE_ATTR_END | 0x18/4}
	case 3:
		header = CacheSlideInfo3{Version: 3, PageSize: 0x1000, PageStartsCount: 2}
	case 4:
		header = CacheSlideInfo4{Version: 4, PageSize: 0x1000, PageStartsOffset: 40, PageStartsCount: 2, PageExtrasOffset: 44, PageExtrasCount: 1, DeltaMask: 0xc0000000}
		starts = []uint16{DYLD_CACHE_SLIDE4_PAGE_NO_REBASE, DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA}
		extras = []uint16{DYLD_CACHE_SLIDE4_PAGE_EXTRA_END | 0x18/4}
	case 5:
		header = CacheSlideInfo5{Version: 5, PageSize: 0x1000, PageStartsCount: 2}
	}
	var info bytes.Buffer
	for _, value := range []any{header, starts, extras} {
		if err := binary.Write(&info, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	if version == 1 {
		info.Write(make([]byte, 128))
	}
	data := make([]byte, 0x3000)
	copy(data[0x100:], info.Bytes())
	binary.LittleEndian.PutUint64(data[0x2018:], 0x18000)
	mapping := &CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{
		Address: 0x10000000, Size: 0x2000, FileOffset: 0x1000, SlideInfoOffset: 0x100, SlideInfoSize: uint64(info.Len()),
	}}
	f := fileReading(data)
	tracker := &slideReadTracker{data: data}
	f.r[f.UUID] = tracker
	f.AddressToSymbol.Set(0x18000, "target")
	return f, mapping, tracker, info.Len() + 4
}

func TestSlideMetadataSharedAcrossConcurrentWalks(t *testing.T) {
	for version := uint32(1); version <= 5; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			f, mapping, tracker, wantBytes := slideCacheFixture(t, version)
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					rs, err := f.GetRebaseInfoForPages(f.UUID, mapping, 1, 2)
					if err != nil {
						t.Error(err)
						return
					}
					if version == 1 {
						if len(rs) != 0 {
							t.Error("version 1 gained rebases")
						}
						return
					}
					if len(rs) != 1 {
						t.Errorf("got %d rebases", len(rs))
						return
					}
					r := rs[0]
					if r.CacheVMAddress != mapping.Address+0x1018 || r.CacheFileOffset != 0x2018 || r.Pointer.Raw() != 0x18000 || r.Target != 0x18000 || r.Symbol != "target" {
						t.Errorf("unexpected rebase: %+v", r)
					}
				})
			}
			wg.Wait()
			if tracker.metadataBytes != wantBytes {
				t.Fatalf("metadata read %d bytes, want exactly %d", tracker.metadataBytes, wantBytes)
			}
			for _, off := range tracker.pointerOffsets {
				if off != 0x2018 {
					t.Fatalf("walk touched another page: %#x", off)
				}
			}
			if version != 1 && len(tracker.pointerOffsets) != 16 {
				t.Fatalf("got %d pointer reads", len(tracker.pointerOffsets))
			}
			// An equivalent mapping copy must reuse metadata, while pointer data and
			// symbols remain live rather than being cached with the tables.
			copyMapping := *mapping
			binary.LittleEndian.PutUint64(tracker.data[0x2018:], 0x18008)
			f.AddressToSymbol.Set(0x18008, "updated")
			rs, err := f.GetRebaseInfoForPages(f.UUID, &copyMapping, 1, 2)
			if err != nil {
				t.Fatal(err)
			}
			if version != 1 && (rs[0].Pointer.Raw() != 0x18008 || rs[0].Target != 0x18008 || rs[0].Symbol != "updated") {
				t.Fatalf("stale pointer or symbol: %+v", rs)
			}
			if tracker.metadataBytes != wantBytes {
				t.Fatal("mapping copy reread metadata")
			}
		})
	}
}

func TestSlideHeaderOnlyAndMixedVersions(t *testing.T) {
	f, mapping, tracker, _ := slideCacheFixture(t, 3)
	// The header remains usable when its tables are truncated.
	tracker.data = tracker.data[:0x100+binary.Size(CacheSlideInfo3{})]
	if err := f.GetSlideInfo(f.UUID, mapping); err != nil {
		t.Fatal(err)
	}
	if f.SlideInfo.GetVersion() != 3 {
		t.Fatal("GetSlideInfo did not publish the header")
	}
	reads := tracker.metadataBytes
	if err := f.GetSlideInfo(f.UUID, mapping); err != nil {
		t.Fatal(err)
	}
	if tracker.metadataBytes != reads {
		t.Fatal("header reread")
	}
	if _, err := f.GetRebaseInfoForPages(f.UUID, mapping, 0, 0); err != io.EOF {
		t.Fatalf("truncated table: %v", err)
	}
	reads = tracker.metadataBytes
	if _, err := f.GetRebaseInfoForPages(f.UUID, mapping, 0, 0); err != io.EOF {
		t.Fatalf("cached table error: %v", err)
	}
	if tracker.metadataBytes != reads {
		t.Fatal("failed table load retried")
	}
	f.SlideInfo = CacheSlideInfo2{Version: 2}
	if err := f.GetSlideInfo(f.UUID, mapping); err == nil || !strings.Contains(err.Error(), "found mixed slide info versions: 2 and 3") {
		t.Fatalf("mixed versions: %v", err)
	}
	f5, m5, _, _ := slideCacheFixture(t, 5)
	f5.SlideInfo = CacheSlideInfo2{Version: 2}
	if err := f5.GetSlideInfo(f5.UUID, m5); err != nil {
		t.Fatal(err)
	}
	if f5.SlideInfo.GetVersion() != 5 {
		t.Fatal("version 5 compatibility changed")
	}
}

func TestSlideMetadataKeyIncludesUUIDAndMapping(t *testing.T) {
	f, mapping, tracker, wantBytes := slideCacheFixture(t, 3)
	uuid := mtypes.UUID{2}
	f.r[uuid] = tracker
	otherMapping := *mapping
	otherMapping.SlideInfoOffset = 0x200
	copy(tracker.data[0x200:], tracker.data[0x100:0x100+mapping.SlideInfoSize])
	for _, key := range []struct {
		uuid    mtypes.UUID
		mapping *CacheMappingWithSlideInfo
	}{{f.UUID, mapping}, {uuid, mapping}, {f.UUID, &otherMapping}} {
		if _, err := f.GetRebaseInfoForPages(key.uuid, key.mapping, 1, 2); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.slideInfos) != 3 || tracker.metadataBytes != 3*wantBytes {
		t.Fatalf("conflated cache keys: %d entries, %d bytes", len(f.slideInfos), tracker.metadataBytes)
	}
}

func TestSlideMetadataReleasedOnClose(t *testing.T) {
	for version := uint32(1); version <= 5; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			f, mapping, tracker, _ := slideCacheFixture(t, version)
			f.closers = map[mtypes.UUID]io.Closer{f.UUID: io.NopCloser(bytes.NewReader(nil))}
			if _, err := f.GetRebaseInfoForPages(f.UUID, mapping, 1, 2); err != nil {
				t.Fatal(err)
			}
			if len(f.slideInfos) != 1 {
				t.Fatalf("got %d cached mappings, want 1", len(f.slideInfos))
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			if len(f.slideInfos) != 0 {
				t.Fatalf("Close retained %d cached mappings", len(f.slideInfos))
			}
			metadataBytes, pointerReads := tracker.metadataBytes, len(tracker.pointerOffsets)
			if _, err := f.GetRebaseInfoForPages(f.UUID, mapping, 1, 2); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("lookup after Close: got %v, want os.ErrClosed", err)
			}
			if len(f.slideInfos) != 0 || tracker.metadataBytes != metadataBytes || len(tracker.pointerOffsets) != pointerReads {
				t.Fatal("lookup after Close repopulated the cache or read slide data")
			}
		})
	}
}
