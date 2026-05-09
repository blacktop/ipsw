package dyld

import (
	"strings"
	"testing"
)

func TestParseTrieExportsRejectsCycles(t *testing.T) {
	_, err := parseTrieExports([]byte{
		0x00,      // no terminal
		0x01,      // one child
		'A', 0x00, // edge
		0x00, // child offset points back to root
	}, 0)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestParseTrieExportsUsesUlebTerminalSizeWidth(t *testing.T) {
	data := []byte{0x82, 0x01} // terminal size 130, encoded in two bytes
	terminal := make([]byte, 130)
	terminal[0] = 0x00 // regular export flags
	terminal[1] = 0x05 // exported address delta
	terminal[129] = 0x01
	data = append(data, terminal...)
	data = append(data, 0x00) // no children

	exports, err := parseTrieExports(data, 0x1000)
	if err != nil {
		t.Fatalf("parseTrieExports returned error: %v", err)
	}
	if len(exports) != 1 {
		t.Fatalf("expected 1 export, got %d", len(exports))
	}
	if exports[0].Address != 0x1005 {
		t.Fatalf("expected address 0x1005, got %#x", exports[0].Address)
	}
}

func TestParseTrieExportsRejectsOversizedTerminal(t *testing.T) {
	_, err := parseTrieExports([]byte{
		0x03,       // terminal size claims three bytes
		0x00, 0x01, // terminal data has no room for child count
	}, 0)
	if err == nil {
		t.Fatal("expected oversized terminal error")
	}
	if !strings.Contains(err.Error(), "exceeds trie size") {
		t.Fatalf("expected bounds error, got %v", err)
	}
}

func TestGetPublicSymbolDuringReentrantParse(t *testing.T) {
	img := &CacheImage{
		Name: "/usr/lib/libA.dylib",
		PublicSymbols: []*Symbol{
			{Name: "_foo", Address: 0x1000},
		},
	}
	if !img.Analysis.State.BeginExports() {
		t.Fatal("failed to mark image as parsing")
	}
	defer img.Analysis.State.FinishExports(false)

	sym, err := img.GetPublicSymbol("_foo")
	if err != nil {
		t.Fatalf("GetPublicSymbol returned error: %v", err)
	}
	if sym.Address != 0x1000 {
		t.Fatalf("expected address 0x1000, got %#x", sym.Address)
	}

	if _, err := img.GetPublicSymbol("_missing"); err == nil {
		t.Fatal("expected missing symbol error")
	}
}
