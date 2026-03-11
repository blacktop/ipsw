package cpp

import (
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func TestTraceLinesReportAnchorMode(t *testing.T) {
	scanner := &Scanner{}
	scanner.stats.anchorMode = anchorModeSymbolExportSymtab
	lines := scanner.TraceLogLines()
	if !strings.Contains(lines[0], "mode=symbol_export_symtab") || !strings.Contains(lines[0], "fallback=false") {
		t.Fatalf("anchor trace line = %q", lines[0])
	}

	scanner.stats.anchorMode = anchorModePreferredFileStringFallback
	lines = scanner.TraceLogLines()
	if !strings.Contains(lines[0], "mode=preferred_file_string_fallback") || !strings.Contains(lines[0], "fallback=true") {
		t.Fatalf("anchor trace fallback line = %q", lines[0])
	}
}

func TestResolvePointerAtReasonAggregatesForwardHitsAndOwnerIndexHits(t *testing.T) {
	root := &macho.File{}
	owner := &macho.File{}
	owner.Sections = []*types.Section{
		{SectionHeader: types.SectionHeader{Name: "__data", Seg: "__DATA", Addr: 0x2000, Size: 0x100}},
	}

	scanner := &Scanner{
		root:            root,
		vmRanges:        []vmRangeOwner{{start: 0x2000, end: 0x2100, file: owner}},
		forwardPointers: map[*macho.File]map[uint64]uint64{owner: {0x2008: 0xfeedface}},
	}

	ptr, ok := scanner.resolvePointerAtReason(nil, 0x2008, pointerReasonMetaPtrDirectCall)
	if !ok || ptr != 0xfeedface {
		t.Fatalf("resolvePointerAtReason = (%#x, %v), want (%#x, true)", ptr, ok, uint64(0xfeedface))
	}

	stats := scanner.stats.pointerReasons[pointerReasonMetaPtrDirectCall]
	if stats.lookups != 1 || stats.forwardHits != 1 || stats.ownerIndexHits != 1 || stats.successes != 1 || stats.misses != 0 {
		t.Fatalf("pointer reason stats = %+v", stats)
	}
}

func TestInferMetaPtrCountersHonorCacheAndBusyGuard(t *testing.T) {
	owner := &macho.File{}
	key := metaInferKey{file: owner, addr: 0x1000, depth: 0}
	scanner := &Scanner{
		metaPtrInfer: map[metaInferKey]cachedMetaPtr{
			key: {value: 0xfeedface, ok: true},
		},
		metaPtrBusy: make(map[metaInferKey]bool),
	}

	if got := scanner.inferMetaPtrFromDirectCallersDepth(owner, 0x1000, 0); got != 0xfeedface {
		t.Fatalf("cached infer = %#x, want %#x", got, uint64(0xfeedface))
	}
	if scanner.stats.inferCalls != 1 || scanner.stats.inferCacheHits != 1 || scanner.stats.inferBusyHits != 0 {
		t.Fatalf("cached infer stats = %+v", scanner.stats)
	}

	scanner = &Scanner{
		metaPtrInfer: make(map[metaInferKey]cachedMetaPtr),
		metaPtrBusy:  map[metaInferKey]bool{key: true},
	}
	if got := scanner.inferMetaPtrFromDirectCallersDepth(owner, 0x1000, 0); got != 0 {
		t.Fatalf("busy infer = %#x, want 0", got)
	}
	if scanner.stats.inferCalls != 1 || scanner.stats.inferBusyHits != 1 {
		t.Fatalf("busy infer stats = %+v", scanner.stats)
	}
}
