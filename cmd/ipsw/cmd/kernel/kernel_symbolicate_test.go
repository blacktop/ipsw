package kernel

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/go-macho"
)

func TestWriteSymbolicatorSchemaDefaultsToStdout(t *testing.T) {
	t.Parallel()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, r); err != nil {
			done <- ""
			return
		}
		done <- buf.String()
	}()

	tempDir := t.TempDir()
	if err := writeSymbolicatorSchema("", tempDir, []byte(`{"hello":"world"}`)); err != nil {
		t.Fatalf("writeSymbolicatorSchema returned error: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}

	if got := <-done; got != "{\"hello\":\"world\"}\n" {
		t.Fatalf("stdout = %q, want %q", got, "{\"hello\":\"world\"}\\n")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "symbolicator.schema.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected schema file created in %s", tempDir)
	}
}

func TestKernelTestLookupAddrsIncludesVtableHeader(t *testing.T) {
	t.Parallel()

	addrs := kernelTestLookupAddrs(0xfffffe0001237010, "vtable for IOService")
	if len(addrs) != 2 {
		t.Fatalf("kernelTestLookupAddrs returned %d addrs, want 2", len(addrs))
	}
	if addrs[0] != 0xfffffe0001237010 || addrs[1] != 0xfffffe0001237000 {
		t.Fatalf("unexpected lookup addrs: %#x", addrs)
	}
}

func TestKernelSymbolMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected string
		actual   string
		want     bool
	}{
		{expected: "vtable for IOService", actual: "__ZTV9IOService", want: true},
		{expected: "IOService::gMetaClass", actual: "__ZN9IOService10gMetaClassE", want: true},
		{expected: "IOService::IOService", actual: "__ZN9IOServiceC2Ev", want: true},
		{expected: "IOService::IOService", actual: "__ZN9IOService14freeSomethingEv", want: false},
	}

	for _, test := range tests {
		if got := kernelSymbolMatches(test.expected, test.actual); got != test.want {
			t.Fatalf("kernelSymbolMatches(%q, %q) = %v, want %v", test.expected, test.actual, got, test.want)
		}
	}
}

func TestMatchKernelTestSymbolReturnsActualNames(t *testing.T) {
	t.Parallel()

	m := &macho.File{}
	m.Symtab = &macho.Symtab{
		Syms: []macho.Symbol{{
			Name:  "__ZTV9IOService",
			Value: 0xfffffe0001237000,
		}},
	}

	matched, actual := matchKernelTestSymbol(m, 0xfffffe0001237010, "vtable for IOService")
	if !matched {
		t.Fatalf("expected vtable symbol to match, actual=%v", actual)
	}
	if len(actual) != 1 || actual[0] != "__ZTV9IOService" {
		t.Fatalf("unexpected actual names: %v", actual)
	}
}
