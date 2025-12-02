//go:build unicorn

package emu

import "github.com/blacktop/ipsw/internal/colors"

// disassembly colors
var colorOp = colors.Bold().SprintfFunc()
var colorRegs = colors.BoldHiBlue().SprintFunc()
var colorImm = colors.BoldMagenta().SprintFunc()
var colorAddr = colors.BoldMagenta().SprintfFunc()
var colorOpCodes = colors.FaintHiWhite().SprintFunc()

// hook colors
var colorHook = colors.FaintHiBlue().SprintFunc()
var colorDetails = colors.ItalicFaintWhite().SprintfFunc()
var colorInterrupt = colors.ItalicBoldHiYellow().SprintfFunc()
var colorChanged = colors.HiYellow().SprintfFunc()
