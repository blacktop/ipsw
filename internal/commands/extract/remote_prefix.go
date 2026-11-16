package extract

import "regexp/syntax"

// prefixMatcher conservatively tests whether an anchored regex can match a
// descendant of a directory. An unanchored pattern requires a full tree walk.
// Running the regex NFA on a prefix handles alternatives and optional slashes
// without guessing a literal prefix or excluding valid files.
type prefixMatcher struct{ program *syntax.Prog }

func newPrefixMatcher(pattern string) *prefixMatcher {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return &prefixMatcher{}
	}
	program, err := syntax.Compile(re.Simplify())
	// Prune only when every match must start at the beginning of the path; a
	// leading '^' is not enough, as in `^a|b$`.
	if err != nil || program.StartCond()&syntax.EmptyBeginText == 0 {
		return &prefixMatcher{}
	}
	return &prefixMatcher{program}
}
func (m *prefixMatcher) directory(name string) bool {
	return m.program == nil || m.prefix(name+"/") || m.prefix("/"+name+"/")
}
func (m *prefixMatcher) prefix(value string) bool {
	states := []uint32{uint32(m.program.Start)}
	previous := rune(-1)
	for _, next := range value {
		var runes []uint32
		seen := map[uint32]bool{}
		matched := false
		var expand func(uint32)
		expand = func(pc uint32) {
			if seen[pc] {
				return
			}
			seen[pc] = true
			instruction := &m.program.Inst[pc]
			switch instruction.Op {
			case syntax.InstAlt, syntax.InstAltMatch:
				expand(instruction.Out)
				expand(instruction.Arg)
			case syntax.InstCapture, syntax.InstNop:
				expand(instruction.Out)
			case syntax.InstEmptyWidth:
				if syntax.EmptyOp(instruction.Arg)&^syntax.EmptyOpContext(previous, next) == 0 {
					expand(instruction.Out)
				}
			case syntax.InstMatch:
				matched = true
			case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				if instruction.MatchRune(next) {
					runes = append(runes, instruction.Out)
				}
			}
		}
		for _, pc := range states {
			expand(pc)
		}
		if matched {
			return true
		}
		if len(runes) == 0 {
			return false
		}
		states = runes
		previous = next
	}
	// Remaining states may accept some suffix. Keeping impossible suffixes is
	// harmless; only a provably dead state permits pruning remote metadata reads.
	return true
}
