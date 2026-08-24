package syms

import (
	"testing"

	"github.com/blacktop/go-macho"
)

func seg(name string) *macho.Segment {
	return &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: name, Addr: 0x1000, Filesz: 0x100}}
}

func file(segs ...*macho.Segment) *macho.File {
	var loads []macho.Load
	for _, s := range segs {
		loads = append(loads, s)
	}
	return &macho.File{FileTOC: macho.FileTOC{Loads: loads}}
}

// TestKextTextSegment is the regression for the UniversalMac com.apple.kec.Libm
// range bug: a stale __TEXT header alongside the relocated __TEXT_EXEC.
func TestKextTextSegment(t *testing.T) {
	staleText := seg("__TEXT")
	textExec := seg("__TEXT_EXEC")

	if got := kextTextSegment(file(staleText, textExec)); got != textExec {
		t.Fatalf("both segments present: got %+v, want __TEXT_EXEC", got)
	}
	if got := kextTextSegment(file(staleText)); got != staleText {
		t.Fatalf("__TEXT_EXEC absent: got %+v, want __TEXT fallback", got)
	}
	if got := kextTextSegment(file()); got != nil {
		t.Fatalf("no segments: got %+v, want nil", got)
	}
}
