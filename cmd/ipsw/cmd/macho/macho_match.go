package macho

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/fatih/color"
)

func executeMachOInstructionScan(
	files []*macho.File,
	labels map[*macho.File]string,
	matcher *disass.InstructionMatcher,
	patterns []disass.InstructionPattern,
	shouldDemangle bool,
	asJSON bool,
	colorEnabled bool,
) error {
	var matches []disass.FunctionMatch
	var err error

	if len(patterns) > 0 {
		matches, err = disass.ScanMachOFunctionsByBytes(files, labels, patterns, shouldDemangle)
	} else {
		matches, err = disass.ScanMachOFunctions(files, labels, matcher, shouldDemangle)
	}
	var errMsg *string
	if err != nil {
		msg := err.Error()
		errMsg = &msg
	}
	if err := renderMachOMatchResults(matches, errMsg, asJSON, colorEnabled); err != nil {
		return err
	}
	return err
}

func renderMachOMatchResults(matches []disass.FunctionMatch, errMsg *string, asJSON bool, colorEnabled bool) error {
	if matches == nil {
		matches = []disass.FunctionMatch{}
	}
	resp := disass.MachOMatchResponse{
		Matches: matches,
		Error:   errMsg,
	}

	if asJSON {
		out, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal match results: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	renderMachOMatchCLI(matches, errMsg, colorEnabled)
	return nil
}

func renderMachOMatchCLI(matches []disass.FunctionMatch, errMsg *string, colorEnabled bool) {
	var headerColor = func(format string, args ...any) {
		fmt.Printf(format, args...)
	}
	var labelColor = func(format string, args ...any) {
		fmt.Printf(format, args...)
	}
	var valueColor = func(format string, args ...any) {
		fmt.Printf(format, args...)
	}
	var matchColor = func(format string, args ...any) {
		fmt.Printf(format, args...)
	}
	var infoColor = func(format string, args ...any) {
		fmt.Printf(format, args...)
	}

	if colorEnabled {
		header := color.New(color.FgCyan, color.Bold)
		headerColor = header.PrintfFunc()
		label := color.New(color.FgHiBlack, color.Bold)
		labelColor = label.PrintfFunc()
		value := color.New(color.FgHiWhite)
		valueColor = value.PrintfFunc()
		match := color.New(color.FgYellow)
		matchColor = match.PrintfFunc()
		info := color.New(color.FgGreen)
		infoColor = info.PrintfFunc()
	}

	if len(matches) == 0 {
		infoColor("No instruction matches found.\n")
	} else {
		for idx, match := range matches {
			if idx > 0 {
				fmt.Println()
			}
			renderFunctionMatchBlock(match, headerColor, labelColor, valueColor, matchColor)
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

func renderFunctionMatchBlock(
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

	if match.Metadata.Image != "" {
		labelColor("  image         : ")
		valueColor("%s\n", match.Metadata.Image)
	}
	labelColor("  start_address : ")
	valueColor("0x%016x\n", match.Metadata.StartAddress)
	labelColor("  start_offset  : ")
	valueColor("0x%x\n", match.Metadata.StartOffset)

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
