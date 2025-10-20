package dyld

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
)

func executeDyldInstructionScan(
	images []*dyld.CacheImage,
	matcher *disass.InstructionMatcher,
	patterns []disass.InstructionPattern,
	shouldDemangle bool,
	asJSON bool,
	colorEnabled bool,
) error {
	var groups []disass.DyldMatch
	var errMsg *string

	for _, image := range images {
		m, err := image.GetMacho()
		if err != nil {
			msg := fmt.Sprintf("failed to parse %s: %v", image.Name, err)
			errMsg = &msg
			break
		}

		label := filepath.Base(image.Name)
		labelMap := map[*macho.File]string{m: label}

		var matches []disass.FunctionMatch
		var scanErr error
		if len(patterns) > 0 {
			matches, scanErr = disass.ScanMachOFunctionsByBytes([]*macho.File{m}, labelMap, patterns, shouldDemangle)
		} else {
			matches, scanErr = disass.ScanMachOFunctions([]*macho.File{m}, labelMap, matcher, shouldDemangle)
		}
		m.Close()
		if scanErr != nil {
			msg := scanErr.Error()
			errMsg = &msg
			break
		}
		if len(matches) > 0 {
			groups = append(groups, disass.DyldMatch{
				Dylib:     image.Name,
				Functions: matches,
			})
		}
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Dylib < groups[j].Dylib
	})

	if err := renderDyldMatchResults(groups, errMsg, asJSON, colorEnabled); err != nil {
		return err
	}
	if errMsg != nil {
		return fmt.Errorf(*errMsg)
	}
	return nil
}

func renderDyldMatchResults(groups []disass.DyldMatch, errMsg *string, asJSON bool, colorEnabled bool) error {
	if groups == nil {
		groups = []disass.DyldMatch{}
	}
	resp := disass.DyldMatchResponse{
		Dylibs: groups,
		Error:  errMsg,
	}

	if asJSON {
		out, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal dyld match results: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	renderDyldMatchCLI(groups, errMsg, colorEnabled)
	return nil
}

func renderDyldMatchCLI(groups []disass.DyldMatch, errMsg *string, colorEnabled bool) {
	var groupColor = func(format string, args ...any) { fmt.Printf(format, args...) }
	var headerColor = func(format string, args ...any) { fmt.Printf(format, args...) }
	var labelColor = func(format string, args ...any) { fmt.Printf(format, args...) }
	var valueColor = func(format string, args ...any) { fmt.Printf(format, args...) }
	var matchColor = func(format string, args ...any) { fmt.Printf(format, args...) }
	var infoColor = func(format string, args ...any) { fmt.Printf(format, args...) }

	if colorEnabled {
		groupColor = color.New(color.FgMagenta, color.Bold).PrintfFunc()
		headerColor = color.New(color.FgCyan, color.Bold).PrintfFunc()
		labelColor = color.New(color.FgHiBlack, color.Bold).PrintfFunc()
		valueColor = color.New(color.FgHiWhite).PrintfFunc()
		matchColor = color.New(color.FgYellow).PrintfFunc()
		infoColor = color.New(color.FgGreen).PrintfFunc()
	}

	if len(groups) == 0 {
		infoColor("No instruction matches found across selected dylibs.\n")
	} else {
		for gIdx, group := range groups {
			if gIdx > 0 {
				fmt.Println()
			}
			groupColor("Dylib: %s\n", group.Dylib)
			for idx, fn := range group.Functions {
				if idx > 0 {
					fmt.Println()
				}
				renderDyldFunctionMatch(fn, headerColor, labelColor, valueColor, matchColor)
			}
		}
	}

	var errLine string
	if errMsg == nil {
		errLine = "error: none"
		if colorEnabled {
			color.New(color.FgGreen).Printf("%s\n", errLine)
		} else {
			fmt.Println(errLine)
		}
	} else {
		errLine = fmt.Sprintf("error: %s", *errMsg)
		if colorEnabled {
			color.New(color.FgRed).Printf("%s\n", errLine)
		} else {
			fmt.Println(errLine)
		}
	}
}

func renderDyldFunctionMatch(
	match disass.FunctionMatch,
	headerColor func(string, ...any),
	labelColor func(string, ...any),
	valueColor func(string, ...any),
	matchColor func(string, ...any),
) {
	headerColor("%s ", match.Function)
	labelColor("(matches: ")
	valueColor("%d", match.MatchCount)
	labelColor(")\n")

	labelColor("  start_address : ")
	valueColor("0x%016x\n", match.Metadata.StartAddress)
	labelColor("  start_offset  : ")
	valueColor("0x%x\n", match.Metadata.StartOffset)

	if match.Metadata.Image != "" {
		labelColor("  image         : ")
		valueColor("%s\n", match.Metadata.Image)
	}

	if match.Metadata.OtherSymbols != nil && len(match.Metadata.OtherSymbols) > 0 {
		labelColor("  other_symbols : ")
		valueColor("%s\n", strings.Join(match.Metadata.OtherSymbols, ", "))
	}

	if match.Stats.EarliestMatchOffset != nil {
		labelColor("  earliest_off  : ")
		valueColor("0x%x\n", *match.Stats.EarliestMatchOffset)
	}

	if len(match.Stats.UniqueInstructionOps) > 0 {
		labelColor("  operations    : ")
		valueColor("%s\n", strings.Join(match.Stats.UniqueInstructionOps, ", "))
	}

	if len(match.Details) > 0 {
		labelColor("  matches:\n")
		for _, detail := range match.Details {
			if len(detail.Bytes) > 0 {
				matchColor("    - 0x%016x: %-32s (% x)\n", detail.Address, detail.Disassembly, detail.Bytes)
			} else {
				matchColor("    - 0x%016x: %s\n", detail.Address, detail.Disassembly)
			}
		}
	}
}
