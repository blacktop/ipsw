package macho

import (
	"fmt"
	"math"
	"sort"

	"github.com/blacktop/go-macho/types"
)

// FunctionMatch represents a match between two functions with confidence scoring
type FunctionMatch struct {
	F1         types.Function
	F2         types.Function
	Confidence float64 // 0-1 score
	MatchType  string  // "exact", "name", "size", "position"
}

// FunctionDelta represents a change in the function list
type FunctionDelta struct {
	Type      string         // "add", "remove", "modify"
	Function  types.Function // the function that was added/removed
	OldFunc   types.Function // for modifications, the old version
	NewFunc   types.Function // for modifications, the new version
	StartIdx  int            // for contiguous blocks
	EndIdx    int            // for contiguous blocks
	BlockSize int            // number of functions in this block
}

// FunctionMatcher handles function list alignment and matching
type FunctionMatcher struct {
	symbolMap1 map[uint64]string
	symbolMap2 map[uint64]string

	// Tuning parameters
	NameWeight     float64 // Weight for name matching (default 0.5)
	SizeWeight     float64 // Weight for size matching (default 0.3)
	PositionWeight float64 // Weight for position proximity (default 0.2)
	MinConfidence  float64 // Minimum confidence to consider a match (default 0.3)
}

// NewFunctionMatcher creates a matcher with default settings
func NewFunctionMatcher(smap1, smap2 map[uint64]string) *FunctionMatcher {
	return &FunctionMatcher{
		symbolMap1:     smap1,
		symbolMap2:     smap2,
		NameWeight:     0.5,
		SizeWeight:     0.3,
		PositionWeight: 0.2,
		MinConfidence:  0.3,
	}
}

// getSymbolName returns the symbol name for a function, or a generated name
func (fm *FunctionMatcher) getSymbolName(f types.Function, symbolMap map[uint64]string) string {
	if sym, ok := symbolMap[f.StartAddr]; ok && sym != "" && sym != "<redacted>" {
		return sym
	}
	return fmt.Sprintf("sub_%x", f.StartAddr)
}

// calculateConfidence computes match confidence between two functions
func (fm *FunctionMatcher) calculateConfidence(f1, f2 types.Function, idx1, idx2, total1, total2 int) (float64, string) {
	name1 := fm.getSymbolName(f1, fm.symbolMap1)
	name2 := fm.getSymbolName(f2, fm.symbolMap2)

	size1 := f1.EndAddr - f1.StartAddr
	size2 := f2.EndAddr - f2.StartAddr

	confidence := 0.0
	matchType := "position"

	// Name matching (excluding generated names)
	if !isGeneratedName(name1) && !isGeneratedName(name2) && name1 == name2 {
		confidence += fm.NameWeight
		matchType = "name"
	}

	// Size matching with tolerance
	if size1 == size2 {
		confidence += fm.SizeWeight
		if matchType == "name" {
			matchType = "exact"
		} else {
			matchType = "size"
		}
	} else if size1 > 0 && size2 > 0 {
		// Partial credit for similar sizes (within 10%)
		ratio := float64(minUint64(size1, size2)) / float64(maxUint64(size1, size2))
		if ratio > 0.9 {
			confidence += fm.SizeWeight * ratio
		}
	}

	// Position proximity
	pos1 := float64(idx1) / float64(maxInt(total1, 1))
	pos2 := float64(idx2) / float64(maxInt(total2, 1))
	posDiff := math.Abs(pos1 - pos2)
	confidence += fm.PositionWeight * (1.0 - posDiff)

	return confidence, matchType
}

// isGeneratedName checks if a name is auto-generated
func isGeneratedName(name string) bool {
	return len(name) > 4 && name[:4] == "sub_"
}

// findAnchors identifies high-confidence matches to use as alignment anchors
func (fm *FunctionMatcher) findAnchors(funcs1, funcs2 []types.Function) []FunctionMatch {
	var anchors []FunctionMatch
	used1 := make(map[int]bool)
	used2 := make(map[int]bool)

	// First pass: exact name + size matches
	for i, f1 := range funcs1 {
		if used1[i] {
			continue
		}
		name1 := fm.getSymbolName(f1, fm.symbolMap1)
		if isGeneratedName(name1) {
			continue
		}

		size1 := f1.EndAddr - f1.StartAddr

		for j, f2 := range funcs2 {
			if used2[j] {
				continue
			}
			name2 := fm.getSymbolName(f2, fm.symbolMap2)
			size2 := f2.EndAddr - f2.StartAddr

			if name1 == name2 && size1 == size2 {
				anchors = append(anchors, FunctionMatch{
					F1:         f1,
					F2:         f2,
					Confidence: 1.0,
					MatchType:  "exact",
				})
				used1[i] = true
				used2[j] = true
				break
			}
		}
	}

	// Sort anchors by position to maintain order
	sort.Slice(anchors, func(i, j int) bool {
		// Find positions in original arrays
		var pos1i, pos1j int
		for k, f := range funcs1 {
			if f.StartAddr == anchors[i].F1.StartAddr {
				pos1i = k
			}
			if f.StartAddr == anchors[j].F1.StartAddr {
				pos1j = k
			}
		}
		return pos1i < pos1j
	})

	return anchors
}

// alignFunctions performs sequence alignment between two function lists
func (fm *FunctionMatcher) alignFunctions(funcs1, funcs2 []types.Function) ([]FunctionMatch, []FunctionDelta) {
	n1, n2 := len(funcs1), len(funcs2)
	matches := []FunctionMatch{}
	deltas := []FunctionDelta{}

	// Find anchor points
	anchors := fm.findAnchors(funcs1, funcs2)

	// Build match map for O(1) lookup
	matched1 := make(map[int]bool)
	matched2 := make(map[int]bool)

	// Mark anchors as matched
	for _, anchor := range anchors {
		for i, f := range funcs1 {
			if f.StartAddr == anchor.F1.StartAddr {
				matched1[i] = true
				break
			}
		}
		for j, f := range funcs2 {
			if f.StartAddr == anchor.F2.StartAddr {
				matched2[j] = true
				break
			}
		}
		matches = append(matches, anchor)
	}

	// Greedy matching between anchors
	anchorIdx := 0
	for i := 0; i < n1; i++ {
		if matched1[i] {
			continue
		}

		// Find the window to search based on nearby anchors
		startJ, endJ := 0, n2
		if anchorIdx < len(anchors) {
			// Limit search to reasonable window around expected position
			expectedJ := int(float64(i) * float64(n2) / float64(n1))
			window := maxInt(20, n2/10) // Search within 10% or 20 functions
			startJ = maxInt(0, expectedJ-window)
			endJ = minInt(n2, expectedJ+window)
		}

		// Find best match in window
		bestJ := -1
		bestConf := 0.0
		bestType := ""

		for j := startJ; j < endJ; j++ {
			if matched2[j] {
				continue
			}

			conf, mtype := fm.calculateConfidence(funcs1[i], funcs2[j], i, j, n1, n2)
			if conf > bestConf && conf >= fm.MinConfidence {
				bestJ = j
				bestConf = conf
				bestType = mtype
			}
		}

		if bestJ >= 0 {
			matches = append(matches, FunctionMatch{
				F1:         funcs1[i],
				F2:         funcs2[bestJ],
				Confidence: bestConf,
				MatchType:  bestType,
			})
			matched1[i] = true
			matched2[bestJ] = true
		}
	}

	// Sort matches by F1 position
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].F1.StartAddr < matches[j].F1.StartAddr
	})

	// Identify unmatched functions and group into contiguous blocks
	deltas = append(deltas, fm.findContiguousRemovals(funcs1, matched1)...)
	deltas = append(deltas, fm.findContiguousAdditions(funcs2, matched2)...)

	// Identify modifications (size changes in matched functions)
	for _, match := range matches {
		size1 := match.F1.EndAddr - match.F1.StartAddr
		size2 := match.F2.EndAddr - match.F2.StartAddr
		if size1 != size2 && match.MatchType != "position" {
			deltas = append(deltas, FunctionDelta{
				Type:    "modify",
				OldFunc: match.F1,
				NewFunc: match.F2,
			})
		}
	}

	return matches, deltas
}

// findContiguousRemovals groups removed functions into blocks
func (fm *FunctionMatcher) findContiguousRemovals(funcs []types.Function, matched map[int]bool) []FunctionDelta {
	var deltas []FunctionDelta

	i := 0
	for i < len(funcs) {
		if matched[i] {
			i++
			continue
		}

		// Start of unmatched block
		start := i
		for i < len(funcs) && !matched[i] {
			i++
		}

		// Create delta for the block
		if i-start >= 3 {
			// Group as a block if 3 or more contiguous
			delta := FunctionDelta{
				Type:      "remove",
				StartIdx:  start,
				EndIdx:    i - 1,
				BlockSize: i - start,
			}
			deltas = append(deltas, delta)
		} else {
			// Individual removals
			for j := start; j < i; j++ {
				deltas = append(deltas, FunctionDelta{
					Type:     "remove",
					Function: funcs[j],
				})
			}
		}
	}

	return deltas
}

// findContiguousAdditions groups added functions into blocks
func (fm *FunctionMatcher) findContiguousAdditions(funcs []types.Function, matched map[int]bool) []FunctionDelta {
	var deltas []FunctionDelta

	i := 0
	for i < len(funcs) {
		if matched[i] {
			i++
			continue
		}

		// Start of unmatched block
		start := i
		for i < len(funcs) && !matched[i] {
			i++
		}

		// Create delta for the block
		if i-start >= 3 {
			// Group as a block if 3 or more contiguous
			delta := FunctionDelta{
				Type:      "add",
				StartIdx:  start,
				EndIdx:    i - 1,
				BlockSize: i - start,
			}
			deltas = append(deltas, delta)
		} else {
			// Individual additions
			for j := start; j < i; j++ {
				deltas = append(deltas, FunctionDelta{
					Type:     "add",
					Function: funcs[j],
				})
			}
		}
	}

	return deltas
}

// Helper functions
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
