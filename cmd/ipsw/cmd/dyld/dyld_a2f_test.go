package dyld

import (
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func TestLookupFunctionKeepsBoundariesWithoutName(t *testing.T) {
	m := &macho.File{FileTOC: macho.FileTOC{Loads: []macho.Load{
		&macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 0x1000}},
		&macho.FunctionStarts{},
	}}}
	// Two synthetic function starts: 0x1020 and 0x1040.
	m.GetFunctions(0x20, 0x20, 0)
	for _, name := range []string{"", "_synthetic"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			fn, err := lookupFunction(m, 0x1028, func(addr uint64) string {
				calls++
				if addr != 0x1020 {
					t.Fatalf("name lookup address = %#x, want function start", addr)
				}
				return name
			})
			want := types.Function{StartAddr: 0x1020, EndAddr: 0x1040, Name: name}
			if err != nil || fn != want || calls != 1 {
				t.Fatalf("lookupFunction() = %#v, %v (%d name calls); want %#v", fn, err, calls, want)
			}
		})
	}
	if _, err := lookupFunction(m, 0x9999, func(uint64) string {
		t.Fatal("attempted naming before establishing a function")
		return ""
	}); err == nil {
		t.Fatal("expected an error for an address outside any function")
	}
}
