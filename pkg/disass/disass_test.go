package disass

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
)

func TestParseStubsASMADRPAndLDRStubDoesNotPanicOnTrailingBR(t *testing.T) {
	data := []byte{
		0x10, 0x00, 0x00, 0xd0, // adrp x16, ...
		0x10, 0x06, 0x40, 0xf9, // ldr  x16, [x16, #0x8]
		0x00, 0x02, 0x1f, 0xd6, // br   x16
	}

	stubs, err := ParseStubsASM(data, 0x100002d78, func(addr uint64) (uint64, error) {
		_ = addr
		return 0x100000ea0, nil
	})
	if err != nil {
		t.Fatalf("ParseStubsASM returned error: %v", err)
	}

	got, ok := stubs[0x100002d78]
	if !ok {
		t.Fatalf("expected stub entry at %#x, got none", uint64(0x100002d78))
	}
	if got != 0x100000ea0 {
		t.Fatalf("unexpected stub target: got %#x, want %#x", got, uint64(0x100000ea0))
	}
}

func TestParseStubsASMADRPAndAddBranchParsesStub(t *testing.T) {
	begin := uint64(0x100002d78)
	data := []byte{
		0x10, 0x00, 0x00, 0xd0, // adrp x16, ...
		0x10, 0x22, 0x00, 0x91, // add  x16, x16, #0x8
		0x00, 0x02, 0x1f, 0xd6, // br   x16
	}

	var results [1024]byte
	adrp, err := disassemble.Decompose(begin, binary.LittleEndian.Uint32(data[0:4]), &results)
	if err != nil {
		t.Fatalf("failed to decompose adrp: %v", err)
	}
	want := adrp.Operands[1].Immediate + 0x8

	readPtrCalled := false
	stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
		readPtrCalled = true
		return 0, fmt.Errorf("unexpected readPtr call for ADRP+ADD+BR stub: %#x", addr)
	})
	if err != nil {
		t.Fatalf("ParseStubsASM returned error: %v", err)
	}
	if readPtrCalled {
		t.Fatalf("expected no readPtr calls for ADRP+ADD+BR stub")
	}

	got, ok := stubs[begin]
	if !ok {
		t.Fatalf("expected branch stub entry at %#x, got none", begin)
	}
	if got != want {
		t.Fatalf("unexpected branch stub target: got %#x, want %#x", got, want)
	}
}

func TestParseStubsASMMismatchedRegistersDoNotCreateStaleStubEntry(t *testing.T) {
	begin := uint64(0x100002d78)

	t.Run("ADRPAddLDRMismatch", func(t *testing.T) {
		data := []byte{
			0x11, 0x00, 0x00, 0xd0, // adrp x17, ...
			0x10, 0x22, 0x00, 0x91, // add  x16, x16, #0x8
			0x10, 0x06, 0x40, 0xf9, // ldr  x16, [x16, #0x8]
		}

		readPtrCalls := 0
		stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
			readPtrCalls++
			return 0x100000ea0, nil
		})
		if err != nil {
			t.Fatalf("ParseStubsASM returned error: %v", err)
		}
		if readPtrCalls != 0 {
			t.Fatalf("expected no readPtr calls on mismatched ADRP/ADD registers, got %d", readPtrCalls)
		}
		if len(stubs) != 0 {
			t.Fatalf("expected no stubs for mismatched ADRP/ADD registers, got %v", stubs)
		}
	})

	t.Run("ADRPAddBRMismatch", func(t *testing.T) {
		data := []byte{
			0x11, 0x00, 0x00, 0xd0, // adrp x17, ...
			0x10, 0x22, 0x00, 0x91, // add  x16, x16, #0x8
			0x00, 0x02, 0x1f, 0xd6, // br   x16
		}

		stubs, err := ParseStubsASM(data, begin, func(addr uint64) (uint64, error) {
			return 0x100000ea0, nil
		})
		if err != nil {
			t.Fatalf("ParseStubsASM returned error: %v", err)
		}
		if len(stubs) != 0 {
			t.Fatalf("expected no stubs for mismatched ADRP/ADD registers, got %v", stubs)
		}
	})
}
