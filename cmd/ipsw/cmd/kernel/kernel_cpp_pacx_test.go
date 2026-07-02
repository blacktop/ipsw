package kernel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/blacktop/ipsw/pkg/kernelcache/pacx"
	"github.com/fatih/color"
)

func syntheticMethodTable() cpp.MethodTable {
	const vt = uint64(0xfffffe0007000000)
	return cpp.MethodTable{
		Class:      "IOService",
		Bundle:     "com.apple.kernel",
		VtableAddr: vt,
		Methods: []cpp.VtableEntry{
			{
				Index: 0, Offset: 0, SlotAddress: vt, Address: 0xfffffe0000010000,
				Symbol: "__ZN9IOService5startEPS_", Method: "start(IOService*)", Class: "IOService",
				Mangled: "__ZN9IOService5startEPS_", Auth: true, PAC: 0x1234, Key: 0, Authoritative: true,
			},
			{
				Index: 1, Offset: 8, SlotAddress: vt + 8, Address: 0xfffffe0000010100,
				Method: "fn_0x8()", Class: "IOService", Auth: true, PAC: 0xabcd, AddrDiv: true,
			},
		},
	}
}

func TestMethodTableToDTOUsesHexStringsAndLowercaseTags(t *testing.T) {
	t.Parallel()

	dto := methodTableToDTO(syntheticMethodTable())
	if dto.VtableAddr != "0xfffffe0007000000" {
		t.Fatalf("vtable_addr = %q, want 0x-hex string", dto.VtableAddr)
	}
	if dto.NumMethods != 2 || len(dto.Methods) != 2 {
		t.Fatalf("num_methods = %d, len = %d, want 2/2", dto.NumMethods, len(dto.Methods))
	}
	if dto.Methods[0].SlotAddr != "0xfffffe0007000000" || dto.Methods[0].Target != "0xfffffe0000010000" {
		t.Fatalf("slot addrs not hex strings: %+v", dto.Methods[0])
	}
	if dto.Methods[0].PACHex != "0x1234" {
		t.Fatalf("pac_hex = %q, want 0x1234", dto.Methods[0].PACHex)
	}

	blob, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal DTO: %v", err)
	}
	out := string(blob)
	for _, want := range []string{`"class":`, `"vtable_addr":`, `"slot_addr":`, `"pac_hex":`, `"offset":0`} {
		if !strings.Contains(out, want) {
			t.Fatalf("DTO JSON missing %q: %s", want, out)
		}
	}
	// Must NOT be the []cpp.Class shape (those use exported field names).
	for _, unwanted := range []string{`"MetaPtr"`, `"SuperMeta"`, `"VtableAddr"`} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("per-slot DTO leaked []Class field %q", unwanted)
		}
	}
}

func TestFormatMethodTableText(t *testing.T) {
	color.NoColor = true

	out := formatMethodTable(syntheticMethodTable())
	for _, want := range []string{
		"IOService",
		"vtab=0xfffffe0007000000",
		"methods=2",
		"0xfffffe0000010000",
		"start(IOService*)",
		"pac=0x1234",
		"fn_0x8()",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("method table text missing %q\n%s", want, out)
		}
	}
}

func TestParsePacxFormats(t *testing.T) {
	t.Parallel()

	got, err := parsePacxFormats("json, r2 ,idapython,json")
	if err != nil {
		t.Fatalf("parsePacxFormats: %v", err)
	}
	want := []string{"json", "r2", "idapython"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parsePacxFormats = %v, want %v (deduped, order preserved)", got, want)
	}

	if _, err := parsePacxFormats("json,bogus"); err == nil {
		t.Fatal("parsePacxFormats should reject an unknown format")
	}
	if _, err := parsePacxFormats("  ,  "); err == nil {
		t.Fatal("parsePacxFormats should reject an empty format list")
	}
}

func TestWritePacxFormatWritesFiles(t *testing.T) {
	t.Parallel()

	index := pacx.BuildIndex(pacx.Meta{Kernelcache: "kc", KernelBase: 0xfffffe0007004000},
		[]cpp.MethodTable{syntheticMethodTable()})
	dir := t.TempDir()

	cases := map[string][]string{
		"json":      {"pacx.json", `"kernelcache": "kc"`},
		"idapython": {"pacx.py", "def pacx_annotate():"},
		"r2":        {"pacx.r2", "CCu "},
	}
	for format, want := range cases {
		path, err := writePacxFormat(index, dir, format, false)
		if err != nil {
			t.Fatalf("writePacxFormat(%s): %v", format, err)
		}
		if filepath.Base(path) != want[0] {
			t.Fatalf("%s wrote %q, want %q", format, filepath.Base(path), want[0])
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(data), want[1]) {
			t.Fatalf("%s content missing %q", format, want[1])
		}
	}

	if _, err := writePacxFormat(index, dir, "bogus", false); err == nil {
		t.Fatal("writePacxFormat should reject an unknown format")
	}
}
