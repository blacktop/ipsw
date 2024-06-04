package disass

import (
	"regexp"

	"github.com/fatih/color"
)

// disassembly colors
var colorOp = color.New(color.Bold).SprintfFunc()
var colorRegs = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorImm = color.New(color.Bold, color.FgMagenta).SprintFunc()
var colorAddr = color.New(color.Bold, color.FgMagenta).SprintfFunc()
var colorOpCodes = color.New(color.Faint, color.FgHiWhite).SprintFunc()
var colorComment = color.New(color.Faint, color.FgWhite).SprintFunc()
var colorLocation = color.New(color.FgHiYellow).SprintfFunc()
var printCurLine = color.New(color.Bold, color.FgBlack, color.BgHiWhite).PrintfFunc()

func ColorOperands(operands string) string {
	if len(operands) > 0 {
		immMatch := regexp.MustCompile(`#?-?0x[0-9a-z]+`)
		operands = immMatch.ReplaceAllStringFunc(operands, func(s string) string {
			return colorImm(s)
		})
		locMatch := regexp.MustCompile(`\sloc_[0-9a-z]+`)
		operands = locMatch.ReplaceAllStringFunc(operands, func(s string) string {
			return colorLocation(s)
		})
		regMatch := regexp.MustCompile(`\W([wxvbhsdqzp][0-9]{1,2}|(c|s)psr(_c)?|pc|sl|sb|fp|ip|sp|lr|fpsid|fpscr|fpexc)`)
		operands = regMatch.ReplaceAllStringFunc(operands, func(s string) string {
			return string(s[0]) + colorRegs(s[1:])
		})
		// TODO: delete this (moved comment coloring into disass module)
		// commentMatch := regexp.MustCompile(`;\s.*$`)
		// operands = commentMatch.ReplaceAllStringFunc(operands, func(s string) string {
		// 	return colorComment(s)
		// })
	}
	return operands
}
