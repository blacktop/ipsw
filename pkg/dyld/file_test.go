package dyld

import "testing"

func TestSlidePagesForRange(t *testing.T) {
	for _, tt := range []struct {
		name               string
		offset, size       uint64
		wantStart, wantEnd uint64
	}{
		{name: "first byte", offset: 0, size: 1, wantStart: 0, wantEnd: 1},
		{name: "exactly one page", offset: 0, size: 0x1000, wantStart: 0, wantEnd: 1},
		{name: "one byte into the next page", offset: 0, size: 0x1001, wantStart: 0, wantEnd: 2},
		{name: "unaligned start and end", offset: 0x1800, size: 0x1000, wantStart: 1, wantEnd: 3},
		{name: "aligned end excludes the next page", offset: 0x3000, size: 0x2000, wantStart: 3, wantEnd: 5},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start, end := SlidePagesForRange(tt.offset, tt.size, 0x1000)
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("SlidePagesForRange(%#x, %#x) = [%d, %d), want [%d, %d)",
					tt.offset, tt.size, start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestSlidePageRange(t *testing.T) {
	for _, tt := range []struct {
		name               string
		start, end         uint64
		count              int
		wantStart, wantEnd uint64
		wantErr            bool
	}{
		{name: "zero end selects every page", start: 0, end: 0, count: 4, wantStart: 0, wantEnd: 4},
		{name: "last page is kept", start: 3, end: 4, count: 4, wantStart: 3, wantEnd: 4},
		{name: "end past the table is clamped", start: 1, end: 9, count: 4, wantStart: 1, wantEnd: 4},
		{name: "start past the table", start: 5, end: 6, count: 4, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := slidePageRange(tt.start, tt.end, tt.count)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("slidePageRange(%d, %d, %d) = [%d, %d), want error", tt.start, tt.end, tt.count, start, end)
				}
				return
			}
			if err != nil || start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf("slidePageRange(%d, %d, %d) = [%d, %d), %v; want [%d, %d)",
					tt.start, tt.end, tt.count, start, end, err, tt.wantStart, tt.wantEnd)
			}
		})
	}
}
