package dyld

import "testing"

func TestJumpSymbolNameDoesNotDoublePrefix(t *testing.T) {
	t.Parallel()

	if got := jumpSymbolName("j__objc_msgSend"); got != "j__objc_msgSend" {
		t.Fatalf("jumpSymbolName double-prefixed: %q", got)
	}
	if got := jumpSymbolName("__stub_helper._objc_msgSend"); got != "j__objc_msgSend" {
		t.Fatalf("jumpSymbolName helper result=%q", got)
	}
}

func TestResolveStubSymbolUsesCachedIslandStubs(t *testing.T) {
	t.Parallel()

	f := &File{
		AddressToSymbol: NewA2STable(16),
		islandStubs: map[uint64]uint64{
			0x1000: 0x2000,
		},
	}
	f.AddressToSymbol.Set(0x2000, "_target")

	got, ok := (DyldDisass{f: f}).resolveStubSymbol(0x1000)
	if !ok {
		t.Fatal("resolveStubSymbol did not resolve cached island stub")
	}
	if got != "j__target" {
		t.Fatalf("resolveStubSymbol=%q, want j__target", got)
	}
}
