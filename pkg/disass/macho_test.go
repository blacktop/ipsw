package disass

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
)

func symbolCacheFixture(t *testing.T) (string, *macho.File, *Config) {
	t.Helper()
	const base = uint64(0x100000000)
	code := append(encodeWords(0x14000002), smallStringCode()...)
	data := make([]byte, 0x500)
	segment := types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 152,
		Addr: base, Memsz: 0x1000, Filesz: uint64(len(data)), Nsect: 1}
	copy(segment.Name[:], "__TEXT")
	section := types.Section64{Addr: base + 0x200, Size: uint64(len(code)), Offset: 0x200}
	copy(section.Name[:], "__text")
	copy(section.Seg[:], "__TEXT")
	var header bytes.Buffer
	for _, value := range []any{
		types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_EXECUTE, NCommands: 2, SizeCommands: 176},
		segment, section,
		types.SymtabCmd{LoadCmd: types.LC_SYMTAB, Len: 24, Symoff: 0x400, Nsyms: 1, Stroff: 0x410, Strsize: 10},
	} {
		if err := binary.Write(&header, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	copy(data, header.Bytes())
	copy(data[0x200:], code)
	symbol := types.Nlist64{Name: 1, Type: types.N_SECT | types.N_EXT, Sect: 1, Value: base + 0x200}
	symbol.Put64(data[0x400:], binary.LittleEndian)
	copy(data[0x410:], "\x00_fixture\x00")
	path := filepath.Join(t.TempDir(), "fixture.macho")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := macho.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return path, f, &Config{Data: code, StartAddress: base + 0x200}
}

func TestMachoSymbolCacheColdWarm(t *testing.T) {
	path, f, cfg := symbolCacheFixture(t)
	cache := filepath.Join(t.TempDir(), "symbols.a2s")
	t.Setenv("TMPDIR", t.TempDir())
	source, err := NewMachoSymbolSource(path)
	if err != nil {
		t.Fatal(err)
	}
	cold := NewMachoDisass(f, cfg)
	if err := cold.OpenOrCreateSymMapFromSource(&cache, source); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("cold open created a placeholder: %v", err)
	}
	if err := cold.Triage(); err != nil {
		t.Fatal(err)
	}
	if err := cold.Analyze(); err != nil {
		t.Fatal(err)
	}
	if ok, from := cold.Contains(cfg.StartAddress + 8); !ok || from != cfg.StartAddress {
		t.Fatal("analysis discarded function triage")
	}
	if err := cold.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	cacheBytes, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[uint64]string
	if err := gob.NewDecoder(bytes.NewReader(cacheBytes)).Decode(&legacy); err != nil || legacy[cfg.StartAddress] != "_fixture" {
		t.Fatalf("legacy cache reader = %v, %v", legacy, err)
	}
	warm := NewMachoDisass(f, cfg)
	if err := warm.OpenOrCreateSymMapFromSource(&cache, source); err != nil {
		t.Fatal(err)
	}
	// If a warm hit reruns image parsing, this extra symbol becomes visible.
	f.Symtab.Syms = append(f.Symtab.Syms, macho.Symbol{Name: "unexpected_reanalysis", Value: cfg.StartAddress + 0x100})
	if err := warm.Triage(); err != nil {
		t.Fatal(err)
	}
	if err := warm.Analyze(); err != nil {
		t.Fatal(err)
	}
	if _, ok := warm.FindSymbol(cfg.StartAddress + 0x100); ok {
		t.Fatal("warm cache reran image-wide analysis")
	}
	if value, ok := warm.FindSwiftString(cfg.StartAddress + 4); !ok || value != "hello" {
		t.Fatalf("warm cache lost per-function Swift strings: %q, %v", value, ok)
	}
	previous := cfg.StartAddress + 4
	cfg.Data, cfg.StartAddress = encodeWords(nop), cfg.StartAddress+0x1000
	if err := warm.Triage(); err != nil {
		t.Fatal(err)
	}
	if err := warm.Analyze(); err != nil {
		t.Fatal(err)
	}
	if _, ok := warm.FindSwiftString(previous); ok {
		t.Fatal("reused image retained the previous function's Swift strings")
	}
	if err := warm.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(cache)
	if err != nil || !bytes.Equal(cacheBytes, after) {
		t.Fatalf("unchanged warm cache was rewritten: %v", err)
	}
}

func TestMachoSymbolCacheRetryDiscardsPartialSymbols(t *testing.T) {
	path, f, cfg := symbolCacheFixture(t)
	t.Setenv("TMPDIR", t.TempDir())
	const dwarfAddress = uint64(0x100000280)
	const staleAddress = uint64(0x100000300)
	dwarf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint64(dwarf[0x408:], dwarfAddress)
	copy(dwarf[0x411:], "_dsym001\x00")
	dwarfPath := filepath.Join(path+".dSYM", "Contents", "Resources", "DWARF", filepath.Base(path))
	if err := os.MkdirAll(filepath.Dir(dwarfPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dwarfPath, dwarf, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "symbols.a2s")
	previous := []byte("previous cache")
	if err := os.WriteFile(cache, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	d := NewMachoDisass(f, cfg)
	if err := d.OpenOrCreateSymMap(&cache, path); err != nil {
		t.Fatal(err)
	}
	loads, symbols := f.Loads, f.Symtab.Syms
	f.Symtab.Syms = append(f.Symtab.Syms, macho.Symbol{Name: "stale_partial", Value: staleAddress})
	f.Loads = append(f.Loads, &macho.DyldInfo{
		LoadCmd: types.LC_DYLD_INFO, Len: 48, ExportOff: 0xffff, ExportSize: 1})
	if err := d.Analyze(); err == nil {
		t.Fatal("expected malformed export table")
	}
	if _, ok := d.FindSymbol(staleAddress); !ok {
		t.Fatal("fixture did not reach partial symbol extraction")
	}
	if err := d.SaveAddrToSymMap(cache); err == nil {
		t.Fatal("failed analysis was saved")
	}
	after, err := os.ReadFile(cache)
	if err != nil || !bytes.Equal(after, previous) {
		t.Fatalf("failed analysis changed the prior cache: %v", err)
	}
	f.Loads, f.Symtab.Syms = loads, symbols
	if err := d.Analyze(); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.FindSymbol(staleAddress); ok {
		t.Fatal("retry retained a stale symbol from the failed attempt")
	}
	if name, ok := d.FindSymbol(dwarfAddress); !ok || name != "_dsym001" {
		t.Fatalf("retry lost preloaded dSYM symbol: %q, %v", name, ok)
	}
	if err := d.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[uint64]string
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&saved); err != nil {
		t.Fatal(err)
	}
	if _, ok := saved[staleAddress]; ok || saved[dwarfAddress] != "_dsym001" {
		t.Fatal("saved cache does not reflect the successful retry")
	}
}

func TestMachoForcedAnalysisDoesNotRetryImage(t *testing.T) {
	_, f, cfg := symbolCacheFixture(t)
	loads := f.Loads
	f.Loads = append(f.Loads, &macho.DyldInfo{
		LoadCmd: types.LC_DYLD_INFO, Len: 48, ExportOff: 0xffff, ExportSize: 1})
	d := NewMachoDisass(f, cfg)
	for i := range uint64(3) {
		address := uint64(0x200000000) + i*4
		f.Symtab.Syms = append(f.Symtab.Syms, macho.Symbol{Name: "later", Value: address})
		cfg.StartAddress += 0x100
		if err := d.Triage(); err != nil {
			t.Fatal(err)
		}
		if err := d.AnalyzeForced(); err == nil {
			t.Fatal("expected malformed export table")
		}
		if _, ok := d.FindSymbol(address); ok != (i == 0) {
			t.Fatalf("image analysis repeated on function %d", i)
		}
		if value, ok := d.FindSwiftString(cfg.StartAddress + 4); !ok || value != "hello" {
			t.Fatalf("function %d lost its Swift string: %q, %v", i, value, ok)
		}
	}
	if err := d.SaveAddrToSymMap(filepath.Join(t.TempDir(), "partial.a2s")); err == nil {
		t.Fatal("forced partial analysis was saved")
	}
	f.Loads = loads
	if err := d.Analyze(); err != nil {
		t.Fatalf("ordinary Analyze could not retry repaired input: %v", err)
	}
}

func TestMachoSymbolCacheMemoAcrossImages(t *testing.T) {
	path, f, cfg := symbolCacheFixture(t)
	t.Setenv("TMPDIR", t.TempDir())
	cache := filepath.Join(t.TempDir(), "images.a2s")
	producer := NewMachoDisass(f, cfg)
	if err := producer.OpenOrCreateSymMap(&cache, path); err != nil {
		t.Fatal(err)
	}
	if err := producer.Analyze(); err != nil {
		t.Fatal(err)
	}
	if err := producer.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	source, err := NewMachoSymbolSource(path)
	if err != nil {
		t.Fatal(err)
	}
	first := NewMachoDisass(f, cfg)
	if err := first.OpenOrCreateSymMapFromSource(&cache, source); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cache); err != nil {
		t.Fatal(err)
	}

	originalType, originalLoads := f.Type, f.Loads
	t.Cleanup(func() { f.Type, f.Loads = originalType, originalLoads })
	f.Type = types.MH_DYLIB
	second := NewMachoDisass(f, cfg)
	if err := second.OpenOrCreateSymMapFromSource(&cache, source); err != nil {
		t.Fatal(err)
	}
	if name, ok := second.FindSymbol(cfg.StartAddress); !ok || name != "_fixture" {
		t.Fatal("second image did not reuse the decoded cache")
	}
	const partialAddress = uint64(0x200000000)
	f.Symtab.Syms = append(f.Symtab.Syms, macho.Symbol{Name: "partial", Value: partialAddress})
	f.Loads = append(f.Loads, &macho.DyldInfo{
		LoadCmd: types.LC_DYLD_INFO, Len: 48, ExportOff: 0xffff, ExportSize: 1})
	if err := second.AnalyzeForced(); err == nil {
		t.Fatal("expected partial analysis")
	}
	f.Type = originalType
	third := NewMachoDisass(f, cfg)
	if err := third.OpenOrCreateSymMapFromSource(&cache, source); err != nil {
		t.Fatal(err)
	}
	if _, ok := third.FindSymbol(partialAddress); ok {
		t.Fatal("failed image contaminated the shared symbol map")
	}
	f.Loads, f.Type = originalLoads, types.MH_DYLIB
	if err := second.Analyze(); err != nil {
		t.Fatal(err)
	}
	if err := second.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	if value, ok := third.FindSymbol(partialAddress); !ok || value != "partial" {
		t.Fatal("completed image did not update the shared symbol map")
	}
}

func TestMachoSymbolCacheRejectsMetadataBeforeMap(t *testing.T) {
	path, f, cfg := symbolCacheFixture(t)
	t.Setenv("TMPDIR", t.TempDir())
	cache := filepath.Join(t.TempDir(), "symbols.a2s")
	d := NewMachoDisass(f, cfg)
	if err := d.OpenOrCreateSymMap(&cache, path); err != nil {
		t.Fatal(err)
	}
	if err := d.Analyze(); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(cache, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteAt([]byte{0xff, 0xff, 0xff, 0xff}, 0)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("corrupt map: %v, %v", writeErr, closeErr)
	}
	for _, demangle := range []bool{true, false} {
		source, err := NewMachoSymbolSource(path)
		if err != nil {
			t.Fatal(err)
		}
		config := *cfg
		config.Demangle = demangle
		fresh := NewMachoDisass(f, &config)
		fresh.initCacheIdentity(source)
		want := ErrCorruptCache
		if demangle {
			want = errStaleMachoCache
		}
		if err := fresh.loadCache(&cache); !errors.Is(err, want) {
			t.Fatalf("demangle=%t: got %v, want %v", demangle, err, want)
		}
	}
}

func TestMachoSymbolCacheCorruptFallbackKeepsRequestedPath(t *testing.T) {
	path, f, cfg := symbolCacheFixture(t)
	t.Setenv("TMPDIR", t.TempDir())
	d := NewMachoDisass(f, cfg)
	requested := filepath.Join(t.TempDir(), "desired.a2s")
	fallback := d.getTempCachePath(&requested)
	corrupt := []byte("corrupt fallback")
	if err := os.WriteFile(fallback, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := requested
	if err := d.OpenOrCreateSymMap(&cache, path); err != nil {
		t.Fatal(err)
	}
	if cache != requested {
		t.Fatalf("cache path = %q, want %q", cache, requested)
	}
	if err := d.Analyze(); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(requested)
	if err != nil {
		t.Fatal(err)
	}
	var symbols map[uint64]string
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&symbols); err != nil || symbols[cfg.StartAddress] != "_fixture" {
		t.Fatalf("requested cache = %v, %v", symbols, err)
	}
	data, err = os.ReadFile(fallback)
	if err != nil || !bytes.Equal(data, corrupt) {
		t.Fatalf("unselected fallback changed: %v", err)
	}
}

func TestMachoSymbolCacheInvalidation(t *testing.T) {
	path, f, cfg := symbolCacheFixture(t)
	cache := filepath.Join(t.TempDir(), "symbols.a2s")
	t.Setenv("TMPDIR", t.TempDir())
	d := NewMachoDisass(f, cfg)
	if err := d.OpenOrCreateSymMap(&cache, path); err != nil {
		t.Fatal(err)
	}
	if err := d.Analyze(); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveAddrToSymMap(cache); err != nil {
		t.Fatal(err)
	}
	complete, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	footerOffset := len(complete) - machoCacheFooterSize
	metadataSize := int(binary.LittleEndian.Uint32(complete[footerOffset:]))
	metadataOffset := footerOffset - metadataSize
	var metadata machoCacheMetadata
	if err := gob.NewDecoder(bytes.NewReader(complete[metadataOffset:footerOffset])).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	metadata.Version--
	var priorMetadata bytes.Buffer
	if err := gob.NewEncoder(&priorMetadata).Encode(metadata); err != nil {
		t.Fatal(err)
	}
	priorRevision := append(bytes.Clone(complete[:metadataOffset]), priorMetadata.Bytes()...)
	priorRevision = binary.LittleEndian.AppendUint32(priorRevision, uint32(priorMetadata.Len()))
	priorRevision = append(priorRevision, machoCacheMagic...)
	var old bytes.Buffer
	if err := gob.NewEncoder(&old).Encode(map[uint64]string{cfg.StartAddress: "legacy_partial"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		data     []byte
		demangle bool
		modify   bool
	}{
		{"legacy", old.Bytes(), false, false},
		{"old revision", priorRevision, false, false},
		{"empty", nil, false, false},
		{"demangle", complete, true, false},
		{"changed source", complete, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(cache, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.modify {
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.Write([]byte{0})
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("modify source: %v, %v", err, closeErr)
				}
			}
			config := *cfg
			config.Demangle = tc.demangle
			fresh := NewMachoDisass(f, &config)
			if err := fresh.OpenOrCreateSymMap(&cache, path); err != nil {
				t.Fatal(err)
			}
			if fresh.analysis.complete || !fresh.EmptySymMap() {
				t.Fatal("unverified cache was accepted")
			}
			fresh.SetStartSym(cfg.StartAddress)
			if err := fresh.SaveAddrToSymMap(cache); err == nil {
				t.Fatal("partial analysis was saved")
			}
			after, err := os.ReadFile(cache)
			if err != nil || !bytes.Equal(after, tc.data) {
				t.Fatalf("prior cache changed before analysis completed: %v", err)
			}
		})
	}
}

func TestMachoDisassChainedPointerConsumers(t *testing.T) {
	for _, format := range []fixupchains.DCPtrKind{
		fixupchains.DYLD_CHAINED_PTR_64_OFFSET,
		fixupchains.DYLD_CHAINED_PTR_ARM64E_USERLAND24,
	} {
		t.Run(format.String(), func(t *testing.T) {
			data := chainedPointerFixture(t, format)
			f, err := macho.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			d := NewMachoDisass(f, &Config{Data: data[0x400:0x408], StartAddress: chainedTestBase + 0x400})
			if target, err := d.ReadAddr(chainedTestBase + 0x1100); err != nil || target != chainedTestBase+0x460 {
				t.Errorf("ReadAddr = %#x, %v", target, err)
			}
			if err := d.Triage(); err != nil {
				t.Fatal(err)
			}
			if ok, detail := d.IsPointer(chainedTestBase + 0x1100); !ok || detail.Pointer != chainedTestBase+0x460 {
				t.Errorf("missing triaged pointer: %v", detail)
			}
			if err := d.parseObjC(); err != nil {
				t.Fatal(err)
			}
			for offset, want := range map[uint64]string{
				0x480: "perform:", 0x1108: "sel_perform:",
				0x1110: "class_ProbeClass", 0x1300: "ProbeClass",
				0x1118: "proto_ProbeProtocol", 0x1480: "ProbeProtocol",
				0x420: `j__objc_msgSend(x0, "perform:")`,
			} {
				if got, ok := d.FindSymbol(chainedTestBase + offset); !ok || got != want {
					t.Errorf("symbol at %#x = %q, %v; want %q", chainedTestBase+offset, got, ok, want)
				}
			}
			for _, offset := range []uint64{0x480, 0x1300, 0x1480} {
				if name, ok := d.FindSymbol(2*chainedTestBase + offset); ok {
					t.Errorf("false alias at %#x: %s", 2*chainedTestBase+offset, name)
				}
			}
		})
	}
}

func movz(rd, hw, imm uint32) uint32 { return 0xd2800000 | hw<<21 | imm<<5 | rd }
func movk(rd, hw, imm uint32) uint32 { return 0xf2800000 | hw<<21 | imm<<5 | rd }

const nop = 0xd503201f

// smallStringCode builds "hello" as a Swift small string: its bytes in x0 and
// the ASCII discriminator (0xE0) with count 5 in the top byte of x1, followed
// by a NOP that ends the sequence.
func smallStringCode() []byte {
	var code []byte
	for _, w := range []uint32{
		movz(0, 0, 0x6568), // "he"
		movk(0, 1, 0x6c6c), // "ll"
		movk(0, 2, 0x006f), // "o"
		movz(1, 0, 0),
		movk(1, 3, 0xe500),
		nop,
	} {
		code = binary.LittleEndian.AppendUint32(code, w)
	}
	return code
}

func findSwiftStrings(t *testing.T, code []byte) map[uint64]string {
	t.Helper()
	d := NewMachoDisass(nil, &Config{Data: code, StartAddress: 0x1000})
	out, err := d.FindSwiftStrings()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFindSwiftStringsSmallString(t *testing.T) {
	want := map[uint64]string{0x1000: "hello"}
	if got := findSwiftStrings(t, smallStringCode()); !maps.Equal(got, want) {
		t.Fatalf("FindSwiftStrings = %v, want %v", got, want)
	}
}

func TestFindSwiftStringsIgnoresTrailingBytes(t *testing.T) {
	want := findSwiftStrings(t, smallStringCode())
	for extra := 1; extra <= 3; extra++ {
		code := append(smallStringCode(), make([]byte, extra)...)
		if got := findSwiftStrings(t, code); !maps.Equal(got, want) {
			t.Errorf("with %d trailing bytes: FindSwiftStrings = %v, want %v", extra, got, want)
		}
	}
	// Without its terminating NOP the string is still pending; a partial word
	// must not be decoded as the instruction that ends it.
	pending := smallStringCode()[:5*4]
	for extra := 1; extra <= 3; extra++ {
		code := append(bytes.Clone(pending), make([]byte, extra)...)
		if got := findSwiftStrings(t, code); len(got) != 0 {
			t.Errorf("a %d-byte partial word ended a pending string: %v", extra, got)
		}
	}
	if got := findSwiftStrings(t, []byte{1, 2, 3}); len(got) != 0 {
		t.Errorf("code shorter than one instruction yielded %v", got)
	}
}

// Words that fail to decode with three of the decoder's failure statuses:
// undefined, unallocated and bad operands.
const (
	wordUndefined   = 0x0c858ca9
	wordUnallocated = 0xffffffff
	wordBadOperands = 0x1918f46c
)

func encodeWords(words ...uint32) []byte {
	var code []byte
	for _, w := range words {
		code = binary.LittleEndian.AppendUint32(code, w)
	}
	return code
}

// TestFindSwiftStringsAcrossBatches runs each sequence at every batch size,
// so batch boundaries and final partial batches fall at every position.
// Words that fail to decode must only advance the address.
func TestFindSwiftStringsAcrossBatches(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		want map[uint64]string
	}{
		{"failures inside a sequence", encodeWords(
			wordUndefined,
			movz(0, 0, 0x6568), movk(0, 1, 0x6c6c), wordUnallocated,
			movk(0, 2, 0x006f), wordBadOperands,
			movz(1, 0, 0), movk(1, 3, 0xe500), nop,
		), map[uint64]string{0x1004: "hello"}},
		{"failed batch between fragments", encodeWords(
			movz(0, 0, 0x6568), movk(0, 1, 0x6c6c), movk(0, 2, 0x006f),
			wordUndefined, wordUnallocated, wordBadOperands,
			movz(1, 0, 0), movk(1, 3, 0xe500), nop,
		), map[uint64]string{0x1000: "hello"}},
		{"strings crossing boundaries", append(smallStringCode(), encodeWords(
			movz(2, 0, 0x6968), movz(3, 0, 0), movk(3, 3, 0xe200), nop,
		)...), map[uint64]string{0x1000: "hello", 0x1018: "hi"}},
		{"pending string before trailing bytes", append(smallStringCode()[:5*4], 0, 0, 0), map[uint64]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for size := 1; size <= len(tc.code)/4+1; size++ {
				d := NewMachoDisass(nil, &Config{Data: tc.code, StartAddress: 0x1000})
				got, err := d.findSwiftStrings(size)
				if err != nil {
					t.Fatalf("batch size %d: %v", size, err)
				}
				if !maps.Equal(got, tc.want) {
					t.Errorf("batch size %d: FindSwiftStrings = %v, want %v", size, got, tc.want)
				}
			}
		})
	}
}
