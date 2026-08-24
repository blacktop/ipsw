package syms

import (
	"testing"

	"github.com/blacktop/go-macho"
)

// fakeSegments implements segmentLookup for a fileset KEXT with a chosen set of
// segments.
type fakeSegments map[string]*macho.Segment

func (f fakeSegments) Segment(name string) *macho.Segment { return f[name] }

func seg(name string, addr, filesz uint64) *macho.Segment {
	return &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: name, Addr: addr, Filesz: filesz}}
}

// TestKextTextSegmentPrefersTextExec is the regression for the UniversalMac
// fileset-KEXT range bug: entries keep a stale pre-relocation __TEXT address
// (identical across kernelcaches) while their code lives in the relocated
// __TEXT_EXEC segment, so the emitted text range must come from __TEXT_EXEC
// when present and fall back to __TEXT only when it is absent.
func TestKextTextSegmentPrefersTextExec(t *testing.T) {
	staleText := seg("__TEXT", 0xfffffe0007130000, 0x7098)
	textExec := seg("__TEXT_EXEC", 0xfffffe0008ad4000, 0x3998)

	got := kextTextSegment(fakeSegments{"__TEXT": staleText, "__TEXT_EXEC": textExec})
	if got != textExec {
		t.Fatalf("both segments present: got %+v, want __TEXT_EXEC %+v", got, textExec)
	}

	got = kextTextSegment(fakeSegments{"__TEXT": staleText})
	if got != staleText {
		t.Fatalf("__TEXT_EXEC absent: got %+v, want __TEXT fallback %+v", got, staleText)
	}

	if got = kextTextSegment(fakeSegments{}); got != nil {
		t.Fatalf("no segments: got %+v, want nil", got)
	}
}
