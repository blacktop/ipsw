package pacx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

func sampleIndex() *Index {
	const vt = uint64(0xfffffe0007000000)
	tables := []cpp.MethodTable{
		{Class: "IOService", Bundle: "com.apple.kernel", VtableAddr: vt, Methods: []cpp.VtableEntry{
			authSlot(0, vt, 0xfffffe0000010000, 0x1234, false, "IOService::start(IOService*)"),
			authSlot(1, vt, 0xfffffe0000010100, 0xabcd, true, "IOService::stop(IOService*)"),
		}},
		{Class: "IOPCIDevice", Bundle: "com.apple.iokit.IOPCIFamily", VtableAddr: vt + 0x1000, Methods: []cpp.VtableEntry{
			authSlot(0, vt+0x1000, 0xfffffe0000020000, 0x1234, false, "IOPCIDevice::start(IOService*)"),
		}},
	}
	meta := Meta{
		Kernelcache: "kernelcache.release.iPhone17,1",
		UUID:        "00000000-0000-0000-0000-000000000000",
		Arch:        "AARCH64",
		FixupFormat: "DYLD_CHAINED_PTR_64_KERNEL_CACHE",
		KernelBase:  0xfffffe0007004000,
	}
	return BuildIndex(meta, tables)
}

func TestWriteJSONShape(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := sampleIndex().WriteJSON(&buf, true); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := buf.String()

	// Addresses are 0x-hex strings; the meta kernel_base is a string.
	for _, want := range []string{
		`"kernel_base": "0xfffffe0007004000"`,
		`"fixup_format": "DYLD_CHAINED_PTR_64_KERNEL_CACHE"`,
		`"slot_addr": "0xfffffe0007000000"`,
		`"pac_hex": "0x1234"`,
		`"vtable_kind": "primary"`,
		`IOService::start(IOService*)`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("pacx.json missing %q\n%s", want, out)
		}
	}

	// Re-parse to confirm valid JSON with the documented top-level shape.
	var doc struct {
		Meta    map[string]any   `json:"meta"`
		Slots   []map[string]any `json:"slots"`
		Forward []map[string]any `json:"forward"`
		Inverse []map[string]any `json:"inverse"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("pacx.json is not valid JSON: %v", err)
	}
	if len(doc.Slots) != 3 {
		t.Fatalf("slots = %d, want 3", len(doc.Slots))
	}
	// offset is a decimal number (not a hex string); pac too.
	if _, ok := doc.Slots[0]["offset"].(float64); !ok {
		t.Fatalf("slot offset should be a JSON number, got %T", doc.Slots[0]["offset"])
	}
	// The colliding (offset=0, pac=0x1234) forward entry has 2 candidates.
	found := false
	for _, f := range doc.Forward {
		if f["offset"].(float64) == 0 && f["pac"].(float64) == float64(0x1234) {
			if got := len(f["candidates"].([]any)); got != 2 {
				t.Fatalf("collision forward candidates = %d, want 2", got)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("collision forward entry (offset=0,pac=0x1234) not found")
	}
}

func TestWriteJSONSlotsOptIn(t *testing.T) {
	t.Parallel()

	// Default (includeSlots=false): slots[] omitted, forward/inverse retained.
	var off bytes.Buffer
	if err := sampleIndex().WriteJSON(&off, false); err != nil {
		t.Fatalf("WriteJSON(false): %v", err)
	}
	var docOff struct {
		Slots   []map[string]any `json:"slots"`
		Forward []map[string]any `json:"forward"`
		Inverse []map[string]any `json:"inverse"`
	}
	if err := json.Unmarshal(off.Bytes(), &docOff); err != nil {
		t.Fatalf("pacx.json (no slots) invalid: %v", err)
	}
	if len(docOff.Slots) != 0 {
		t.Fatalf("slots omitted by default: got %d, want 0", len(docOff.Slots))
	}
	if strings.Contains(off.String(), `"slots"`) {
		t.Fatalf("pacx.json should not contain a slots key by default:\n%s", off.String())
	}
	if len(docOff.Forward) == 0 || len(docOff.Inverse) == 0 {
		t.Fatalf("forward/inverse must remain by default: forward=%d inverse=%d", len(docOff.Forward), len(docOff.Inverse))
	}

	// Opt-in (includeSlots=true): slots[] present.
	var on bytes.Buffer
	if err := sampleIndex().WriteJSON(&on, true); err != nil {
		t.Fatalf("WriteJSON(true): %v", err)
	}
	if !strings.Contains(on.String(), `"slots"`) {
		t.Fatalf("pacx.json should contain slots[] when opted in")
	}
}

func TestWriteIDAPythonEmbedsIndexAndHelpers(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := sampleIndex().WriteIDAPython(&buf); err != nil {
		t.Fatalf("WriteIDAPython: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"KERNEL_BASE = 0xfffffe0007004000",
		"FORWARD = json.loads(",
		"INVERSE = json.loads(",
		"def pacx_candidates(offset, pac):",
		"def pacx_xrefs(target):",
		"def pacx_annotate():",
		"idaapi.get_imagebase()",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("pacx.py missing %q", want)
		}
	}

	// The embedded FORWARD blob must be JSON with integer addresses so the Python
	// rebase math works. Extract and parse it.
	fwdJSON := between(t, out, `FORWARD = json.loads(r"""`, `""")`)
	var fwd []struct {
		Offset     uint64 `json:"offset"`
		PAC        uint16 `json:"pac"`
		Candidates []struct {
			Target   uint64 `json:"target"`
			SlotAddr uint64 `json:"slot_addr"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(fwdJSON), &fwd); err != nil {
		t.Fatalf("embedded FORWARD is not valid JSON: %v\n%s", err, fwdJSON)
	}
	if len(fwd) == 0 {
		t.Fatal("embedded FORWARD is empty")
	}
	for _, f := range fwd {
		if f.Offset == 0 && f.PAC == 0x1234 && len(f.Candidates) != 2 {
			t.Fatalf("embedded collision entry candidates = %d, want 2", len(f.Candidates))
		}
	}
}

func TestWriteR2CommentsAndFlags(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := sampleIndex().WriteR2(&buf); err != nil {
		t.Fatalf("WriteR2: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"CCu ",
		"@ 0xfffffe0007000000",
		"f pacx.",
		"= 0xfffffe0000010000",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("pacx.r2 missing %q\n%s", want, out)
		}
	}
	// Flag names must be radare2-safe (no spaces, no parens).
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "f ") {
			continue
		}
		name := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(line, "f "), "=", 2)[0])
		if strings.ContainsAny(name, " ()*:,<>") {
			t.Fatalf("unsafe r2 flag name %q", name)
		}
	}
}

func TestSanitizeFlagFallsBackToTarget(t *testing.T) {
	t.Parallel()

	if got := sanitizeFlag("", 0xdead); got != "fn_dead" {
		t.Fatalf("sanitizeFlag empty = %q, want fn_dead", got)
	}
	if got := sanitizeFlag("IOService::start(IOService*)", 0); strings.ContainsAny(got, " ()*:") {
		t.Fatalf("sanitizeFlag left unsafe chars: %q", got)
	}
}

// between returns the substring of s between the first occurrence of start and
// the next occurrence of end after it.
func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("start marker %q not found", start)
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		t.Fatalf("end marker %q not found", end)
	}
	return s[i : i+j]
}
