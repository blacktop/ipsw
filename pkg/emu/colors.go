package emu

import "github.com/fatih/color"

// disassembly colors
var colorOp = color.New(color.Bold).SprintfFunc()
var colorRegs = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorImm = color.New(color.Bold, color.FgMagenta).SprintFunc()
var colorAddr = color.New(color.Bold, color.FgMagenta).SprintfFunc()
var colorOpCodes = color.New(color.Faint, color.FgHiWhite).SprintFunc()

// hook colors
var colorHook = color.New(color.Faint, color.FgHiBlue).SprintFunc()
var colorDetails = color.New(color.Italic, color.Faint, color.FgWhite).SprintfFunc()
var colorInterrupt = color.New(color.Italic, color.Bold, color.FgHiYellow).SprintfFunc()
