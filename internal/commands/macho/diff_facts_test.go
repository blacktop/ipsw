package macho

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestComparisonFactsFromDiffInfoPreservesReferenceSemantics(t *testing.T) {
	info := &DiffInfo{
		LoadCmdHash: "load-command-digest",
		Imports:     []string{"/usr/lib/libz.dylib", "/usr/lib/libSystem.B.dylib", "/usr/lib/libz.dylib"},
		Sections: []section{
			{Name: "__TEXT.__cstring", Size: 17, Type: types.CstringLiterals, HashMode: hashCStringsMultiset, Hash: "cstring-digest"},
			{Name: "__TEXT.__text", Size: 31, Type: types.Regular, HashMode: hashSkip},
			{Name: "__DATA.__data", Size: 19, Type: types.Regular, HashMode: hashVerbatim},
		},
		Functions: 2,
		Starts: []types.Function{
			{StartAddr: 0x1000, EndAddr: 0x1010},
			{StartAddr: 0x1020, EndAddr: 0x1030},
		},
		Symbols: []string{
			"___block_literal_global.123",
			"___block_literal_global.456",
			"/AppleInternal/Library/BuildRoots/one/usr/local/lib/raw.o",
		},
		// SymbolMap contains post-extraction enrichment and must not enter the
		// normalized raw-name facts.
		SymbolMap: map[uint64]string{0x1000: "EnrichedSymbolName"},
	}
	cpu := ComparisonFactsCPU{Type: 0x0100000c, Subtype: 2, Architecture: "arm64e"}
	facts := ComparisonFactsFromDiffInfo(info, cpu, true, ReferenceComparisonDiffConfig())

	if facts.SchemaVersion != ComparisonFactsSchemaVersion || facts.Policy.Version != ReferenceComparisonPolicyVersion {
		t.Fatalf("unexpected schema/policy: %+v", facts)
	}
	if facts.Provenance.ReferenceSource != "ipsw@88dec284d70abb0a9d56fb438b5a3dc4c7ac1801" ||
		facts.Provenance.DiffInfoGenerator != "internal/commands/macho.GenerateContainerDiffInfo" {
		t.Fatalf("unexpected reference provenance: %+v", facts.Provenance)
	}
	if facts.CPU != cpu {
		t.Fatalf("cpu = %+v, want %+v", facts.CPU, cpu)
	}
	if slices.Contains(facts.NormalizedRawNames, "EnrichedSymbolName") {
		t.Fatalf("enriched name leaked into raw names: %v", facts.NormalizedRawNames)
	}
	wantRaw := []string{
		"/AppleInternal/Library/BuildRoots/<BUILDROOT>/usr/local/lib/raw.o",
		"___block_literal_global",
	}
	if !slices.Equal(facts.NormalizedRawNames, wantRaw) {
		t.Fatalf("normalized raw names = %v, want %v", facts.NormalizedRawNames, wantRaw)
	}
	if len(facts.Sections) != 3 {
		t.Fatalf("sections = %d, want 3", len(facts.Sections))
	}
	if facts.Sections[0].Type != uint32(types.CstringLiterals) ||
		facts.Sections[0].Hash.Policy != "normalized_cstring_multiset_sha256" ||
		facts.Sections[0].Hash.State != "present" {
		t.Fatalf("cstring section lost type/hash policy: %+v", facts.Sections[0])
	}
	if facts.Sections[1].Hash.State != "excluded" || facts.Sections[2].Hash.State != "unavailable" {
		t.Fatalf("section hash states = %+v, want excluded then unavailable", facts.Sections[1:])
	}
	if facts.LoadCommands.State != "present" || facts.LoadCommands.SHA256 != info.LoadCmdHash {
		t.Fatalf("load commands = %+v", facts.LoadCommands)
	}
	if facts.FunctionCount != 2 || len(facts.FunctionStarts) != 2 || facts.Policy.CompareFunctionStarts {
		t.Fatalf("function facts/policy = count %d starts %+v compare %t",
			facts.FunctionCount, facts.FunctionStarts, facts.Policy.CompareFunctionStarts)
	}
	if facts.SymbolTableCoverage != "unsupported" {
		t.Fatalf("symbol table coverage = %q, want unsupported", facts.SymbolTableCoverage)
	}

	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	var roundTrip ComparisonFacts
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("unmarshal facts: %v", err)
	}
	reencoded, err := json.Marshal(roundTrip)
	if err != nil {
		t.Fatalf("remarshal facts: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("wire round trip changed bytes:\nfirst:  %s\nsecond: %s", encoded, reencoded)
	}
}

func TestCodeSignatureFactsDoNotClaimContainerAbsence(t *testing.T) {
	containerEntitlements, _ := codeSignatureFacts(nil, true)
	if containerEntitlements.Status != "unavailable" {
		t.Fatalf("container entitlements status = %q, want unavailable", containerEntitlements.Status)
	}
	standaloneEntitlements, _ := codeSignatureFacts(nil, false)
	if standaloneEntitlements.Status != "absent" {
		t.Fatalf("standalone entitlements status = %q, want absent", standaloneEntitlements.Status)
	}
}
