package disass

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/demangle"
)

// InstructionMatcher provides helpers for matching assembly instructions using
// exact string comparisons and optional regular expressions.
type InstructionMatcher struct {
	patterns       []string
	normalized     []string
	regex          *regexp.Regexp
	rawRegexSource string
}

// normalizeCondenses whitespace and lowercases the input so that stylistic
// differences in formatting do not impact matching.
func normalizeInstruction(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(s)), " "))
}

// NewInstructionMatcher builds a matcher from literal instruction patterns and
// an optional regex. An error is returned if the regex fails to compile.
func NewInstructionMatcher(patterns []string, regexPattern string) (*InstructionMatcher, error) {
	m := &InstructionMatcher{}

	for _, p := range patterns {
		if p == "" {
			continue
		}
		m.patterns = append(m.patterns, p)
		m.normalized = append(m.normalized, normalizeInstruction(p))
	}

	if regexPattern != "" {
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", regexPattern, err)
		}
		m.regex = re
		m.rawRegexSource = regexPattern
	}

	return m, nil
}

// HasCriteria reports whether the matcher has any patterns or regex configured.
func (m *InstructionMatcher) HasCriteria() bool {
	return len(m.patterns) > 0 || m.regex != nil
}

// Match returns true when the provided instruction string satisfies either an
// exact pattern match (after normalization) or the configured regular
// expression.
func (m *InstructionMatcher) Match(instruction string) bool {
	if !m.HasCriteria() {
		return false
	}

	if m.regex != nil && m.regex.MatchString(instruction) {
		return true
	}

	if len(m.patterns) == 0 {
		return false
	}

	norm := normalizeInstruction(instruction)
	for _, p := range m.normalized {
		if p == norm {
			return true
		}
	}

	return false
}

// InstructionMatchDetail captures the address and disassembly of a matched
// instruction. It is omitted from JSON output but can be used by CLI renderers.
type InstructionMatchDetail struct {
	Address      uint64
	Disassembly  string
	FileLabel    string
	FunctionName string
	Bytes        []byte
}

// MatchStats contains aggregate information for a function match.
type MatchStats struct {
	MatchCount           int      `json:"match_count"`
	EarliestMatchOffset  *uint64  `json:"earliest_match_offset,omitempty"`
	UniqueInstructionOps []string `json:"unique_operations,omitempty"`
}

// MatchMetadata captures supporting information for a matched function.
type MatchMetadata struct {
	Image        string   `json:"image,omitempty"`
	StartOffset  uint64   `json:"start_offset"`
	StartAddress uint64   `json:"start_address"`
	OtherSymbols []string `json:"other_symbols"`
}

// FunctionMatch represents a function that satisfied the search criteria.
type FunctionMatch struct {
	Function   string                   `json:"function"`
	MatchCount int                      `json:"match_count"`
	Stats      MatchStats               `json:"stats"`
	Metadata   MatchMetadata            `json:"metadata"`
	Details    []InstructionMatchDetail `json:"-"`
}

// MachOMatchResponse is the top-level response for MachO scans.
type MachOMatchResponse struct {
	Matches []FunctionMatch `json:"matches"`
	Error   *string         `json:"error"`
}

// DyldMatch groups matched functions by dylib for dyld_shared_cache scans.
type DyldMatch struct {
	Dylib     string          `json:"dylib"`
	Functions []FunctionMatch `json:"functions"`
}

// DyldMatchResponse is the top-level response for dyld_shared_cache scans.
type DyldMatchResponse struct {
	Dylibs []DyldMatch `json:"dylibs"`
	Error  *string     `json:"error"`
}

// InstructionPattern captures the assembled bytes for a given instruction.
type InstructionPattern struct {
	Instruction string
	Bytes       []byte
	Mnemonic    string
}

var encodingPattern = regexp.MustCompile(`encoding:\s*\[([^\]]+)\]`)

// AssembleInstructionPatterns assembles the provided ARM64 instructions into
// raw byte sequences using llvm-mc. The host must have llvm-mc accessible in
// PATH or via xcrun.
func AssembleInstructionPatterns(instructions []string) ([]InstructionPattern, error) {
	if len(instructions) == 0 {
		return nil, nil
	}

	llvmPath, err := findLLVMMC()
	if err != nil {
		return nil, err
	}

	var input strings.Builder
	input.WriteString(".text\n")
	for _, ins := range instructions {
		if strings.TrimSpace(ins) == "" {
			continue
		}
		input.WriteString("    ")
		input.WriteString(strings.TrimSpace(ins))
		input.WriteByte('\n')
	}

	cmd := exec.Command(llvmPath, "-triple=arm64-apple-macos", "-mattr=+all", "-show-encoding")
	cmd.Stdin = strings.NewReader(input.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to assemble instructions with llvm-mc: %w\n%s", err, strings.TrimSpace(string(output)))
	}

	matches := encodingPattern.FindAllStringSubmatch(string(output), -1)
	if len(matches) != len(instructions) {
		return nil, fmt.Errorf("expected %d encodings from llvm-mc, got %d\n%s", len(instructions), len(matches), strings.TrimSpace(string(output)))
	}

	patterns := make([]InstructionPattern, 0, len(instructions))
	for idx, match := range matches {
		byteList := strings.Split(match[1], ",")
		encoded := make([]byte, 0, len(byteList))
		for _, entry := range byteList {
			entry = strings.TrimSpace(entry)
			entry = strings.TrimPrefix(strings.ToLower(entry), "0x")
			if entry == "" {
				continue
			}
			val, err := strconv.ParseUint(entry, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("failed to parse llvm-mc byte %q: %w", entry, err)
			}
			encoded = append(encoded, byte(val))
		}
		if len(encoded) == 0 {
			return nil, fmt.Errorf("instruction %q produced no encoding", instructions[idx])
		}
		mnemonic := ""
		if fields := strings.Fields(strings.TrimSpace(instructions[idx])); len(fields) > 0 {
			mnemonic = fields[0]
		}
		patterns = append(patterns, InstructionPattern{
			Instruction: strings.TrimSpace(instructions[idx]),
			Bytes:       encoded,
			Mnemonic:    mnemonic,
		})
	}

	return patterns, nil
}

func findLLVMMC() (string, error) {
	if path, err := exec.LookPath("llvm-mc"); err == nil {
		return path, nil
	}
	if xcrunPath, err := exec.LookPath("xcrun"); err == nil {
		cmd := exec.Command(xcrunPath, "--find", "llvm-mc")
		if out, err := cmd.Output(); err == nil {
			if resolved := strings.TrimSpace(string(out)); resolved != "" {
				return resolved, nil
			}
		}
	}
	return "", errors.New("llvm-mc not found; install LLVM (e.g. `brew install llvm`) or ensure llvm-mc is on PATH")
}

// ScanMachOFunctions iterates over the supplied MachO files and returns all
// functions that satisfy the provided instruction matcher. The optional labels
// map is used to annotate metadata with the originating image name.
func ScanMachOFunctions(files []*macho.File, labels map[*macho.File]string, matcher *InstructionMatcher, shouldDemangle bool) ([]FunctionMatch, error) {
	var results []FunctionMatch

	for _, file := range files {
		if file == nil {
			continue
		}

		for _, fn := range file.GetFunctions() {
			if fn.EndAddr <= fn.StartAddr {
				continue
			}

			data, err := file.GetFunctionData(fn)
			if err != nil {
				log.WithField("start_addr", fmt.Sprintf("%#x", fn.StartAddr)).WithError(err).Warn("failed to read function data")
				continue
			}

			var details []InstructionMatchDetail
			var matchCount int
			opset := make(map[string]struct{})
			var earliestOffset uint64
			var haveEarliest bool

			funcName, otherSymbols := resolveMachOFunctionName(file, fn, shouldDemangle)
			label := ""
			if labels != nil {
				label = labels[file]
			}

			var instrValue uint32
			var buf [1024]byte
			addr := fn.StartAddr
			reader := bytes.NewReader(data)

			for {
				if err := binary.Read(reader, binary.LittleEndian, &instrValue); err != nil {
					if err != io.EOF {
						log.WithField("address", fmt.Sprintf("%#x", addr)).WithError(err).Debug("failed to read instruction")
					}
					break
				}

				instr, err := disassemble.Decompose(addr, instrValue, &buf)
				if err != nil {
					log.WithField("address", fmt.Sprintf("%#x", addr)).WithError(err).Debug("failed to decode instruction")
					addr += 4
					continue
				}

				disassText := instr.String()
				if matcher.Match(disassText) {
					matchCount++
					details = append(details, InstructionMatchDetail{
						Address:      instr.Address,
						Disassembly:  disassText,
						FileLabel:    label,
						FunctionName: funcName,
					})
					offset := instr.Address - fn.StartAddr
					if !haveEarliest || offset < earliestOffset {
						earliestOffset = offset
						haveEarliest = true
					}
					if op := instr.Operation.String(); op != "" {
						opset[op] = struct{}{}
					}
				}

				addr += 4
			}

			if matchCount == 0 {
				continue
			}

			startOffset, err := file.GetOffset(fn.StartAddr)
			if err != nil {
				log.WithField("start_addr", fmt.Sprintf("%#x", fn.StartAddr)).WithError(err).Debug("failed to compute start offset")
				startOffset = 0
			}

			var uniqOps []string
			if len(opset) > 0 {
				uniqOps = make([]string, 0, len(opset))
				for op := range opset {
					uniqOps = append(uniqOps, op)
				}
				sort.Strings(uniqOps)
			}

			stats := MatchStats{MatchCount: matchCount}
			if haveEarliest {
				eo := earliestOffset
				stats.EarliestMatchOffset = &eo
			}
			if len(uniqOps) > 0 {
				stats.UniqueInstructionOps = uniqOps
			}

			results = append(results, FunctionMatch{
				Function:   funcName,
				MatchCount: matchCount,
				Stats:      stats,
				Metadata: MatchMetadata{
					Image:        label,
					StartOffset:  startOffset,
					StartAddress: fn.StartAddr,
					OtherSymbols: otherSymbols,
				},
				Details: details,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Function == results[j].Function {
			return results[i].Metadata.StartAddress < results[j].Metadata.StartAddress
		}
		return results[i].Function < results[j].Function
	})

	return results, nil
}

// ScanMachOFunctionsByBytes searches for the supplied instruction byte patterns
// across executable sections, attributing matches back to functions.
func ScanMachOFunctionsByBytes(files []*macho.File, labels map[*macho.File]string, patterns []InstructionPattern, shouldDemangle bool) ([]FunctionMatch, error) {
	if len(patterns) == 0 {
		return nil, nil
	}

	type accumulator struct {
		match   *FunctionMatch
		opSet   map[string]struct{}
		label   string
		funcRef types.Function
	}

	resultsMap := make(map[string]*accumulator)
	var firstErr error

	for _, file := range files {
		if file == nil {
			continue
		}

		label := ""
		if labels != nil {
			label = labels[file]
		}

		funcs := file.GetFunctions()
		if len(funcs) == 0 {
			continue
		}

		for _, sec := range file.Sections {
			if sec == nil || !isExecutableSection(sec) || sec.Size == 0 {
				continue
			}
			data, err := sec.Data()
			if err != nil {
				log.WithError(err).WithField("section", fmt.Sprintf("%s.%s", sec.Seg, sec.Name)).Debug("failed to read section data")
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			baseAddr := sec.Addr

			for _, pattern := range patterns {
				idx := 0
				for idx < len(data) {
					pos := bytes.Index(data[idx:], pattern.Bytes)
					if pos == -1 {
						break
					}
					matchAddr := baseAddr + uint64(idx+pos)
					fn, ok := findFunctionForAddr(funcs, matchAddr)
					if !ok {
						idx += pos + 1
						continue
					}

					key := fmt.Sprintf("%p:%#x", file, fn.StartAddr)
					acc, exists := resultsMap[key]
					if !exists {
						name, other := resolveMachOFunctionName(file, fn, shouldDemangle)
						startOffset, err := file.GetOffset(fn.StartAddr)
						if err != nil {
							if firstErr == nil {
								firstErr = err
							}
							startOffset = 0
						}
						fm := &FunctionMatch{
							Function: name,
							Metadata: MatchMetadata{
								Image:        label,
								StartOffset:  startOffset,
								StartAddress: fn.StartAddr,
								OtherSymbols: other,
							},
						}
						acc = &accumulator{
							match:   fm,
							opSet:   make(map[string]struct{}),
							label:   label,
							funcRef: fn,
						}
						resultsMap[key] = acc
					}

					acc.match.MatchCount++
					acc.match.Stats.MatchCount++

					offset := matchAddr - acc.funcRef.StartAddr
					if acc.match.Stats.EarliestMatchOffset == nil || offset < *acc.match.Stats.EarliestMatchOffset {
						tmp := offset
						acc.match.Stats.EarliestMatchOffset = &tmp
					}

					if pattern.Mnemonic != "" {
						acc.opSet[pattern.Mnemonic] = struct{}{}
					}

					acc.match.Details = append(acc.match.Details, InstructionMatchDetail{
						Address:      matchAddr,
						Disassembly:  pattern.Instruction,
						FileLabel:    acc.label,
						FunctionName: acc.match.Function,
						Bytes:        append([]byte(nil), pattern.Bytes...),
					})

					idx += pos + 1
				}
			}
		}
	}

	var results []FunctionMatch
	for _, acc := range resultsMap {
		if len(acc.opSet) > 0 {
			ops := make([]string, 0, len(acc.opSet))
			for op := range acc.opSet {
				ops = append(ops, op)
			}
			sort.Strings(ops)
			acc.match.Stats.UniqueInstructionOps = ops
		}
		results = append(results, *acc.match)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Function == results[j].Function {
			return results[i].Metadata.StartAddress < results[j].Metadata.StartAddress
		}
		return results[i].Function < results[j].Function
	})

	return results, firstErr
}

func isExecutableSection(sec *types.Section) bool {
	if sec.Seg == "__TEXT" && strings.HasPrefix(sec.Name, "__text") {
		return true
	}
	if sec.Flags.IsPureInstructions() || sec.Flags.IsSomeInstructions() {
		return true
	}
	return false
}

func findFunctionForAddr(funcs []types.Function, addr uint64) (types.Function, bool) {
	if len(funcs) == 0 {
		return types.Function{}, false
	}
	idx := sort.Search(len(funcs), func(i int) bool {
		return funcs[i].StartAddr > addr
	})
	if idx == 0 {
		fn := funcs[0]
		if addr >= fn.StartAddr && addr < fn.EndAddr {
			return fn, true
		}
		return types.Function{}, false
	}
	fn := funcs[idx-1]
	if addr >= fn.StartAddr && addr < fn.EndAddr {
		return fn, true
	}
	return types.Function{}, false
}

func resolveMachOFunctionName(file *macho.File, fn types.Function, shouldDemangle bool) (string, []string) {
	name := strings.TrimSpace(fn.Name)
	if shouldDemangle && name != "" {
		name = demangle.Do(name, false, false)
	}

	var otherSymbols []string
	if syms, err := file.FindAddressSymbols(fn.StartAddr); err == nil && len(syms) > 0 {
		seen := make(map[string]struct{})
		for _, sym := range syms {
			symName := sym.Name
			if shouldDemangle {
				symName = demangle.Do(symName, false, false)
			}
			if _, ok := seen[symName]; ok {
				continue
			}
			seen[symName] = struct{}{}
			otherSymbols = append(otherSymbols, symName)
		}
		if name == "" && len(otherSymbols) > 0 {
			name = otherSymbols[0]
			if len(otherSymbols) > 1 {
				otherSymbols = otherSymbols[1:]
			} else {
				otherSymbols = []string{}
			}
		} else {
			filtered := otherSymbols[:0]
			for _, symName := range otherSymbols {
				if symName != name {
					filtered = append(filtered, symName)
				}
			}
			otherSymbols = filtered
		}
	}

	if name == "" {
		name = fmt.Sprintf("sub_%x", fn.StartAddr)
	}

	return name, otherSymbols
}
