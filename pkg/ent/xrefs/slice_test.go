package xrefs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockMemory struct {
	ptrs     map[uint64]uint64
	raws     map[uint64]uint64
	strs     map[uint64]string
	ptrSlide uint64
}

func (m mockMemory) ReadPointer(addr uint64) (uint64, error) {
	ptr, ok := m.ptrs[addr]
	if !ok {
		return 0, fmt.Errorf("no pointer at %#x", addr)
	}
	if m.ptrSlide != 0 && ptr != 0 {
		ptr += m.ptrSlide
	}
	return ptr, nil
}

func (m mockMemory) ReadUint64(addr uint64) (uint64, error) {
	raw, ok := m.raws[addr]
	if ok {
		return raw, nil
	}
	raw, ok = m.ptrs[addr]
	if !ok {
		return 0, fmt.Errorf("no uint64 at %#x", addr)
	}
	return raw, nil
}

func (m mockMemory) ReadCString(addr uint64) (string, error) {
	str, ok := m.strs[addr]
	if !ok {
		return "", fmt.Errorf("no cstring at %#x", addr)
	}
	return str, nil
}

func TestKernelIOUserClientTargetsSplitBySignature(t *testing.T) {
	tests := []struct {
		name      string
		symbol    string
		wantOK    bool
		wantCanon string
		wantKey   int
	}{
		{
			name:      "singular qualified",
			symbol:    "IOUserClient::copyClientEntitlement(task_t, char const*)",
			wantOK:    true,
			wantCanon: "IOUserClient::copyClientEntitlement",
			wantKey:   1,
		},
		{
			name:      "singular short",
			symbol:    "copyClientEntitlement",
			wantOK:    true,
			wantCanon: "IOUserClient::copyClientEntitlement",
			wantKey:   1,
		},
		{
			name:      "vnode",
			symbol:    "IOUserClient::copyClientEntitlementVnode(vnode*, task_t, char const*)",
			wantOK:    true,
			wantCanon: "IOUserClient::copyClientEntitlementVnode",
			wantKey:   2,
		},
		{
			name:   "short alias does not match other classes",
			symbol: "OtherUserClient::copyClientEntitlement(task_t, char const*)",
		},
		{
			name:   "plural has no single key",
			symbol: "IOUserClient::copyClientEntitlements(task_t, OSArray*)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, ok := matchTarget(SourceKernelcache, tt.symbol)
			if ok != tt.wantOK {
				t.Fatalf("ok=%t, want %t", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if target.Canonical != tt.wantCanon || target.KeyReg != tt.wantKey {
				t.Fatalf("target=%#v, want canonical %q key x%d", target, tt.wantCanon, tt.wantKey)
			}
		})
	}
}

func TestKernelCFunctionTargetsMatchDemangledSignatures(t *testing.T) {
	target, ok := matchTarget(SourceKernelcache, "IOTaskHasEntitlement(task_t, char const*)")
	if !ok {
		t.Fatal("IOTaskHasEntitlement signature did not match")
	}
	if target.Canonical != "IOTaskHasEntitlement" || target.KeyReg != 1 {
		t.Fatalf("target=%#v, want IOTaskHasEntitlement key x1", target)
	}
}

func TestScanFunctionResolvesADRPAddCString(t *testing.T) {
	base := uint64(0x100000000)
	targetAddr := uint64(0x100001000)
	keyAddr := uint64(0x100002120)
	data := words(
		encADRP(1, base, keyAddr),
		encADDImm(1, 1, keyAddr&0xfff),
		encBL(base+8, targetAddr),
	)

	records := scanFunction(functionScan{
		source:       SourceKernelcache,
		image:        "com.apple.iokit.IOSurface",
		callerSymbol: "IOSurfaceRootUserClient::init_check",
		data:         data,
		start:        base,
		targets: map[uint64][]targetSpec{
			targetAddr: {{Source: SourceKernelcache, Canonical: "IOTaskHasEntitlement", KeyReg: 1, ValueReg: -1}},
		},
		mem: mockMemory{strs: map[uint64]string{keyAddr: "com.apple.private.iosurface.client"}},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if !records[0].Resolved || records[0].Key != "com.apple.private.iosurface.client" || records[0].Extra["slice_notes"] != "" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
}

func TestScanFunctionRejectsADDRegisterAsImmediate(t *testing.T) {
	base := uint64(0x100000000)
	targetAddr := uint64(0x100001000)
	keyAddr := uint64(0x100002120)
	data := words(
		encADRP(2, base, keyAddr),
		encADDReg(1, 2, 3),
		encBL(base+8, targetAddr),
	)

	records := scanFunction(functionScan{
		source: SourceKernelcache,
		image:  "com.apple.driver.Test",
		data:   data,
		start:  base,
		targets: map[uint64][]targetSpec{
			targetAddr: {{Source: SourceKernelcache, Canonical: "IOTaskHasEntitlement", KeyReg: 1, ValueReg: -1}},
		},
		mem: mockMemory{strs: map[uint64]string{keyAddr: "com.apple.private.wrong"}},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if records[0].Resolved || records[0].Key != "" || records[0].Extra["slice_notes"] != "indirect" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
}

func TestScanFunctionResolvesCFString(t *testing.T) {
	base := uint64(0x100000000)
	targetAddr := uint64(0x100001000)
	cfAddr := uint64(0x100003040)
	strAddr := uint64(0x100004000)
	data := words(
		encADRP(1, base, cfAddr),
		encADDImm(1, 1, cfAddr&0xfff),
		encBL(base+8, targetAddr),
	)

	records := scanFunction(functionScan{
		source: SourceDSC,
		image:  "/System/Library/Frameworks/Security.framework/Security",
		data:   data,
		start:  base,
		targets: map[uint64][]targetSpec{
			targetAddr: {{Source: SourceDSC, Canonical: "SecTaskCopyValueForEntitlement", KeyReg: 1, ValueReg: -1}},
		},
		mem: mockMemory{
			ptrs: map[uint64]uint64{cfAddr + 16: strAddr},
			strs: map[uint64]string{strAddr: "com.apple.private.security.allow-untrusted"},
		},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if got := records[0].Key; got != "com.apple.private.security.allow-untrusted" {
		t.Fatalf("key=%q", got)
	}
}

func TestScanFunctionResolvesObjCSelectorValueForEntitlement(t *testing.T) {
	base := uint64(0x100000000)
	msgSend := uint64(0x100010000)
	selRef := uint64(0x100002000)
	selStr := uint64(0x100003000)
	keyAddr := uint64(0x100004040)
	target, ok := matchTarget(SourceDSC, "_objc_msgSend")
	if !ok {
		t.Fatal("objc_msgSend target did not match")
	}
	data := words(
		encADRP(1, base, selRef),
		encLDRUnsigned(1, 1, selRef&0xfff),
		encADRP(2, base+8, keyAddr),
		encADDImm(2, 2, keyAddr&0xfff),
		encBL(base+16, msgSend),
	)

	records := scanFunction(functionScan{
		source: SourceDSC,
		image:  "/System/Library/Frameworks/Foundation.framework/Foundation",
		data:   data,
		start:  base,
		targets: map[uint64][]targetSpec{
			msgSend: {target},
		},
		mem: mockMemory{
			ptrs: map[uint64]uint64{selRef: selStr},
			strs: map[uint64]string{
				selStr:  "valueForEntitlement:",
				keyAddr: "com.apple.private.xpc.test",
			},
		},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if records[0].CheckFn != "-[NSXPCConnection valueForEntitlement:]" || records[0].Key != "com.apple.private.xpc.test" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
}

func TestScanFunctionResolvesObjCValueForEntitlementStub(t *testing.T) {
	base := uint64(0x100000000)
	stub := uint64(0x100010000)
	keyAddr := uint64(0x100004040)
	target, ok := matchTarget(SourceDSC, "_objc_msgSend$valueForEntitlement:")
	if !ok {
		t.Fatal("objc_msgSend$valueForEntitlement: target did not match")
	}
	data := words(
		encADRP(2, base, keyAddr),
		encADDImm(2, 2, keyAddr&0xfff),
		encBL(base+8, stub),
	)

	records := scanFunction(functionScan{
		source: SourceDSC,
		image:  "/System/Library/Frameworks/Foundation.framework/Foundation",
		data:   data,
		start:  base,
		targets: map[uint64][]targetSpec{
			stub: {target},
		},
		mem: mockMemory{strs: map[uint64]string{keyAddr: "com.apple.private.xpc.test"}},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if records[0].CheckFn != "-[NSXPCConnection valueForEntitlement:]" || records[0].Key != "com.apple.private.xpc.test" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
}

func TestScanFunctionBLRThroughRegisterEmitsUnresolvedParam(t *testing.T) {
	base := uint64(0x100000000)
	targetAddr := uint64(0x100005000)
	data := words(
		encADRP(16, base, targetAddr),
		encADDImm(16, 16, targetAddr&0xfff),
		encBLR(16),
	)

	records := scanFunction(functionScan{
		source: SourceKernelcache,
		image:  "com.apple.driver.Test",
		data:   data,
		start:  base,
		targets: map[uint64][]targetSpec{
			targetAddr: {{Source: SourceKernelcache, Canonical: "IOTaskHasEntitlement", KeyReg: 1, ValueReg: -1}},
		},
		mem: mockMemory{},
	})

	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	if records[0].Resolved || records[0].Key != "" || records[0].Extra["slice_notes"] != "param" {
		t.Fatalf("unexpected record: %#v", records[0])
	}
}

func TestScanFunctionExpandsLiteralCFArrayKeys(t *testing.T) {
	base := uint64(0x100000000)
	targetAddr := uint64(0x100001000)
	arrayAddr := uint64(0x100002000)
	valuesAddr := uint64(0x100003000)
	keyOne := uint64(0x100004000)
	keyTwo := uint64(0x100005000)
	data := words(
		encADRP(1, base, arrayAddr),
		encADDImm(1, 1, arrayAddr&0xfff),
		encBL(base+8, targetAddr),
	)

	records := scanFunction(functionScan{
		source: SourceDSC,
		image:  "/System/Library/Frameworks/Security.framework/Security",
		data:   data,
		start:  base,
		targets: map[uint64][]targetSpec{
			targetAddr: {{Source: SourceDSC, Canonical: "SecTaskCopyValuesForEntitlements", KeyReg: 1, ValueReg: -1, KeyArray: true}},
		},
		mem: mockMemory{
			ptrs: map[uint64]uint64{
				arrayAddr + 16: 2,
				arrayAddr + 24: valuesAddr,
				valuesAddr:     keyOne,
				valuesAddr + 8: keyTwo,
			},
			strs: map[uint64]string{
				keyOne: "application-identifier",
				keyTwo: "keychain-access-groups",
			},
		},
	})

	if len(records) != 2 {
		t.Fatalf("records=%d, want 2", len(records))
	}
	if records[0].Key != "application-identifier" || records[1].Key != "keychain-access-groups" {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestScanFunctionExpandsLiteralCFArrayKeysWithSlidPointers(t *testing.T) {
	base := uint64(0x100000000)
	targetAddr := uint64(0x100001000)
	arrayAddr := uint64(0x100002000)
	valuesAddr := uint64(0x100003000)
	keyOne := uint64(0x100004000)
	keyTwo := uint64(0x100005000)
	slide := uint64(0x1000000000)
	data := words(
		encADRP(1, base, arrayAddr),
		encADDImm(1, 1, arrayAddr&0xfff),
		encBL(base+8, targetAddr),
	)

	records := scanFunction(functionScan{
		source: SourceDSC,
		image:  "/System/Library/Frameworks/Security.framework/Security",
		data:   data,
		start:  base,
		targets: map[uint64][]targetSpec{
			targetAddr: {{Source: SourceDSC, Canonical: "SecTaskCopyValuesForEntitlements", KeyReg: 1, ValueReg: -1, KeyArray: true}},
		},
		mem: mockMemory{
			ptrSlide: slide,
			ptrs: map[uint64]uint64{
				arrayAddr + 24:         valuesAddr,
				valuesAddr + slide:     keyOne,
				valuesAddr + slide + 8: keyTwo,
			},
			raws: map[uint64]uint64{
				arrayAddr + 16: 2,
			},
			strs: map[uint64]string{
				keyOne + slide: "application-identifier",
				keyTwo + slide: "keychain-access-groups",
			},
		},
	})

	if len(records) != 2 {
		t.Fatalf("records=%d, want 2: %#v", len(records), records)
	}
	if records[0].Key != "application-identifier" || records[1].Key != "keychain-access-groups" {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestAddResolvedAddressTargetFiltersSelectorTargets(t *testing.T) {
	global := map[uint64][]targetSpec{
		0x1000: {
			{Source: SourceDSC, Canonical: "xpc_connection_has_entitlement", KeyReg: 1, ValueReg: -1},
			{Source: SourceDSC, Canonical: "-[NSXPCConnection valueForEntitlement:]", KeyReg: 2, ValueReg: -1, Selector: "valueForEntitlement:"},
		},
	}

	targets := make(map[uint64][]targetSpec)
	if !addResolvedAddressTarget(targets, global, 0x2000, 0x1000, false) {
		t.Fatal("expected non-selector target to be added")
	}
	if len(targets[0x2000]) != 1 || targets[0x2000][0].Canonical != "xpc_connection_has_entitlement" {
		t.Fatalf("unexpected filtered targets: %#v", targets[0x2000])
	}

	targets = make(map[uint64][]targetSpec)
	if !addResolvedAddressTarget(targets, global, 0x2000, 0x1000, true) {
		t.Fatal("expected selector target to be added")
	}
	if len(targets[0x2000]) != 2 {
		t.Fatalf("targets=%d, want 2", len(targets[0x2000]))
	}
}

func TestKernelSymbolMapCandidatesIncludeAncestorOutputDirs(t *testing.T) {
	root := t.TempDir()
	outputDir := filepath.Join(root, "ipsw-symbolicator")
	if err := os.Mkdir(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(outputDir, "kernelcache.release.iPhone18,1.symbols.json")
	if err := os.WriteFile(want, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "extract", "23E254__iPhone18,1", "kernelcache.release.iPhone18,1")
	candidates := kernelSymbolMapCandidates(path)
	for _, got := range candidates {
		if got == want {
			return
		}
	}
	t.Fatalf("candidate %q not found in %#v", want, candidates)
}

func TestWriteJSONLDeterministicOrderingAndKeys(t *testing.T) {
	records := []Record{
		{Source: "kernelcache", Image: "b", Callsite: "0x2", CheckFn: "B", Extra: map[string]string{}},
		{Source: "dsc", Image: "z", Callsite: "0x9", CheckFn: "A", Extra: map[string]string{"slice_notes": "param"}},
		{Source: "dsc", Image: "a", Callsite: "0x1", CheckFn: "A", Extra: map[string]string{}},
	}
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, records); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines=%d", len(lines))
	}
	if !strings.Contains(lines[0], `"source":"dsc"`) || !strings.Contains(lines[0], `"image":"a"`) {
		t.Fatalf("records not sorted: %s", buf.String())
	}
	if !strings.HasPrefix(lines[0], `{"callsite":`) || !strings.Contains(lines[1], `"extra":{"slice_notes":"param"},"image":`) {
		t.Fatalf("keys not deterministically ordered: %s", buf.String())
	}
}

func words(ws ...uint32) []byte {
	var buf bytes.Buffer
	for _, w := range ws {
		_ = binary.Write(&buf, binary.LittleEndian, w)
	}
	return buf.Bytes()
}

func encADRP(rd int, pc, target uint64) uint32 {
	pcPage := pc &^ 0xfff
	targetPage := target &^ 0xfff
	pages := int64(targetPage-pcPage) / 0x1000
	imm := uint32(uint64(pages) & ((1 << 21) - 1))
	immlo := imm & 0x3
	immhi := (imm >> 2) & 0x7ffff
	return 0x90000000 | (immlo << 29) | (immhi << 5) | uint32(rd)
}

func encADDImm(rd, rn int, imm uint64) uint32 {
	return 0x91000000 | (uint32(imm&0xfff) << 10) | (uint32(rn) << 5) | uint32(rd)
}

func encADDReg(rd, rn, rm int) uint32 {
	return 0x8b000000 | (uint32(rm) << 16) | (uint32(rn) << 5) | uint32(rd)
}

func encLDRUnsigned(rt, rn int, imm uint64) uint32 {
	return 0xf9400000 | (uint32((imm/8)&0xfff) << 10) | (uint32(rn) << 5) | uint32(rt)
}

func encBL(pc, target uint64) uint32 {
	off := int64(target-pc) / 4
	return 0x94000000 | (uint32(uint64(off)) & 0x03ffffff)
}

func encBLR(rn int) uint32 {
	return 0xd63f0000 | (uint32(rn) << 5)
}
