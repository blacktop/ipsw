package macho

import (
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestFunctionMatcher(t *testing.T) {
	tests := []struct {
		name       string
		funcs1     []types.Function
		funcs2     []types.Function
		symbolMap1 map[uint64]string
		symbolMap2 map[uint64]string
		wantAdds   int
		wantRems   int
		wantMods   int
	}{
		{
			name: "identical functions",
			funcs1: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1100},
				{StartAddr: 0x2000, EndAddr: 0x2200},
			},
			funcs2: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1100},
				{StartAddr: 0x2000, EndAddr: 0x2200},
			},
			wantAdds: 0,
			wantRems: 0,
			wantMods: 0,
		},
		{
			name: "bulk additions - 13 new functions",
			funcs1: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1100},
				{StartAddr: 0x2000, EndAddr: 0x2200},
			},
			funcs2: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1100},
				{StartAddr: 0x1500, EndAddr: 0x1600}, // new
				{StartAddr: 0x1600, EndAddr: 0x1700}, // new
				{StartAddr: 0x1700, EndAddr: 0x1800}, // new
				{StartAddr: 0x1800, EndAddr: 0x1900}, // new
				{StartAddr: 0x1900, EndAddr: 0x1A00}, // new
				{StartAddr: 0x1A00, EndAddr: 0x1B00}, // new
				{StartAddr: 0x1B00, EndAddr: 0x1C00}, // new
				{StartAddr: 0x1C00, EndAddr: 0x1D00}, // new
				{StartAddr: 0x1D00, EndAddr: 0x1E00}, // new
				{StartAddr: 0x1E00, EndAddr: 0x1F00}, // new
				{StartAddr: 0x1F00, EndAddr: 0x2000}, // new
				{StartAddr: 0x2100, EndAddr: 0x2150}, // new
				{StartAddr: 0x2150, EndAddr: 0x2180}, // new
				{StartAddr: 0x2000, EndAddr: 0x2200},
			},
			wantAdds: 1, // Should be grouped as 1 block
			wantRems: 0,
			wantMods: 0,
		},
		{
			name: "size changes with matching names",
			funcs1: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1100}, // size 0x100
				{StartAddr: 0x2000, EndAddr: 0x2200}, // size 0x200
			},
			funcs2: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1150}, // size 0x150 (changed)
				{StartAddr: 0x2000, EndAddr: 0x2200}, // size 0x200 (same)
			},
			symbolMap1: map[uint64]string{
				0x1000: "_funcA",
				0x2000: "_funcB",
			},
			symbolMap2: map[uint64]string{
				0x1000: "_funcA",
				0x2000: "_funcB",
			},
			wantAdds: 0,
			wantRems: 0,
			wantMods: 1,
		},
		{
			name: "interleaved changes",
			funcs1: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1100},
				{StartAddr: 0x2000, EndAddr: 0x2200},
				{StartAddr: 0x3000, EndAddr: 0x3300},
				{StartAddr: 0x4000, EndAddr: 0x4400},
			},
			funcs2: []types.Function{
				{StartAddr: 0x1000, EndAddr: 0x1100},
				{StartAddr: 0x1500, EndAddr: 0x1600}, // new
				{StartAddr: 0x3000, EndAddr: 0x3300},
				{StartAddr: 0x3500, EndAddr: 0x3600}, // new
			},
			wantAdds: 2, // 2 individual additions
			wantRems: 2, // 2 removals
			wantMods: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewFunctionMatcher(tt.symbolMap1, tt.symbolMap2)
			_, deltas := matcher.alignFunctions(tt.funcs1, tt.funcs2)

			adds, rems, mods := 0, 0, 0
			for _, delta := range deltas {
				switch delta.Type {
				case "add":
					if delta.BlockSize > 0 {
						adds++ // Count block as 1
					} else {
						adds++
					}
				case "remove":
					if delta.BlockSize > 0 {
						rems++ // Count block as 1
					} else {
						rems++
					}
				case "modify":
					mods++
				}
			}

			if adds != tt.wantAdds {
				t.Errorf("got %d additions, want %d", adds, tt.wantAdds)
			}
			if rems != tt.wantRems {
				t.Errorf("got %d removals, want %d", rems, tt.wantRems)
			}
			if mods != tt.wantMods {
				t.Errorf("got %d modifications, want %d", mods, tt.wantMods)
			}
		})
	}
}

func TestConfidenceScoring(t *testing.T) {
	smap1 := map[uint64]string{0x1000: "_testFunc"}
	smap2 := map[uint64]string{0x2000: "_testFunc"}

	matcher := NewFunctionMatcher(smap1, smap2)

	f1 := types.Function{StartAddr: 0x1000, EndAddr: 0x1100}
	f2 := types.Function{StartAddr: 0x2000, EndAddr: 0x2100}

	conf, mtype := matcher.calculateConfidence(f1, f2, 0, 0, 10, 10)

	// Should have name match + size match + position match
	expectedConf := matcher.NameWeight + matcher.SizeWeight + matcher.PositionWeight
	if conf != expectedConf {
		t.Errorf("expected confidence %f, got %f", expectedConf, conf)
	}

	if mtype != "exact" {
		t.Errorf("expected match type 'exact', got '%s'", mtype)
	}
}
