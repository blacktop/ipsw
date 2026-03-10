package signature

import (
	"testing"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

func TestCPPClassSymbols(t *testing.T) {
	t.Parallel()

	symbols := cppClassSymbols(cpp.Class{
		Name:           "IOService",
		Ctor:           0xfffffe0001234000,
		MetaPtr:        0xfffffe0001235000,
		MetaVtableAddr: 0xfffffe0001236000,
		VtableAddr:     0xfffffe0001237000,
	})

	if len(symbols) != 4 {
		t.Fatalf("cppClassSymbols returned %d symbols, want 4", len(symbols))
	}

	want := map[uint64]string{
		0xfffffe0001234000: "IOService::IOService",
		0xfffffe0001235000: "IOService::gMetaClass",
		0xfffffe0001236000: "vtable for IOService::MetaClass",
		0xfffffe0001237000: "vtable for IOService",
	}

	for _, symbol := range symbols {
		if got, ok := want[symbol.addr]; !ok || got != symbol.name {
			t.Fatalf("unexpected symbol %#x => %q", symbol.addr, symbol.name)
		}
	}
}

func TestAddKernelCPPClassesSkipsConflicts(t *testing.T) {
	t.Parallel()

	sm := NewSymbolMap()
	if err := sm.Add(0xfffffe0001234000, "ExistingCtor"); err != nil {
		t.Fatalf("failed to seed symbol map: %v", err)
	}

	added := sm.addKernelCPPClasses([]cpp.Class{{
		Name:           "IOService",
		Ctor:           0xfffffe0001234000,
		MetaPtr:        0xfffffe0001235000,
		MetaVtableAddr: 0xfffffe0001236000,
		VtableAddr:     0xfffffe0001237000,
	}})

	if added != 3 {
		t.Fatalf("addKernelCPPClasses added %d symbols, want 3", added)
	}
	if got := sm[0xfffffe0001234000]; got != "ExistingCtor" {
		t.Fatalf("constructor symbol was overwritten: got %q", got)
	}
	if got := sm[0xfffffe0001235000]; got != "IOService::gMetaClass" {
		t.Fatalf("meta class symbol = %q, want IOService::gMetaClass", got)
	}
	if got := sm[0xfffffe0001236000]; got != "vtable for IOService::MetaClass" {
		t.Fatalf("meta vtable symbol = %q, want vtable for IOService::MetaClass", got)
	}
	if got := sm[0xfffffe0001237000]; got != "vtable for IOService" {
		t.Fatalf("vtable symbol = %q, want vtable for IOService", got)
	}
}
