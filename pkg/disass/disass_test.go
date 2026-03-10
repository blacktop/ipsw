package disass

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/blacktop/arm64-cgo/disassemble"
)

type stubDisass struct {
	data      []byte
	startAddr uint64
	asJSON    bool
}

func (s stubDisass) Triage() error                          { return nil }
func (s stubDisass) IsFunctionStart(uint64) (bool, string)  { return false, "" }
func (s stubDisass) IsLocation(uint64) bool                 { return false }
func (s stubDisass) IsBranchLocation(uint64) (bool, uint64) { return false, 0 }
func (s stubDisass) IsData(uint64) (bool, *AddrDetails)     { return false, nil }
func (s stubDisass) IsPointer(uint64) (bool, *AddrDetails)  { return false, nil }
func (s stubDisass) FindSymbol(uint64) (string, bool)       { return "", false }
func (s stubDisass) FindSwiftString(uint64) (string, bool)  { return "", false }
func (s stubDisass) GetCString(uint64) (string, error)      { return "", fmt.Errorf("no cstring") }
func (s stubDisass) Demangle() bool                         { return false }
func (s stubDisass) Quite() bool                            { return true }
func (s stubDisass) Color() bool                            { return false }
func (s stubDisass) AsJSON() bool                           { return s.asJSON }
func (s stubDisass) Data() []byte                           { return s.data }
func (s stubDisass) StartAddr() uint64                      { return s.startAddr }
func (s stubDisass) Middle() uint64                         { return 0 }
func (s stubDisass) ReadAddr(uint64) (uint64, error)        { return 0, fmt.Errorf("no pointer") }

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

	var decoder disassemble.Decoder
	var adrp disassemble.Inst
	if err := decoder.DecomposeInto(begin, binary.LittleEndian.Uint32(data[0:4]), &adrp); err != nil {
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

func TestDisassembleJSONPreservesDisassemblyString(t *testing.T) {
	out := Disassemble(stubDisass{
		data:      []byte{0x1f, 0x20, 0x03, 0xd5}, // nop
		startAddr: 0x1000,
		asJSON:    true,
	})

	var got []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON disassembly output: %v\noutput=%s", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(got))
	}
	if addr, ok := got[0]["addr"].(float64); !ok || uint64(addr) != 0x1000 {
		t.Fatalf("unexpected instruction address payload: %#v", got[0]["addr"])
	}
	disassText, ok := got[0]["disass"].(string)
	if !ok {
		t.Fatalf("expected disass string in JSON payload, got %#v", got[0]["disass"])
	}
	if !strings.Contains(disassText, "nop") {
		t.Fatalf("expected JSON disassembly to contain nop, got %q", disassText)
	}
}
