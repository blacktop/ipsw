// Centralized TTY-aware color output management.
// Requires initialization (Init) to be called after cli parsing has been done - 
// from cobra PersistentPreRun() callback

package colors

import (
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

func Init() {
	// color.NoColor already set by fatih/color init() based on:
	// TTY detection, Cygwin terminal, TERM=dumb, NO_COLOR env
	isTTY := !color.NoColor

	noColor := viper.GetBool("no-color")
	forceColor := viper.GetBool("color") && !noColor

	color.NoColor = noColor || !(isTTY || forceColor)
}

// Active reports whether color output is active.
// Determined by TTY detection, --color, and --no-color flags.
func Active() bool {
	return !color.NoColor
}

// New creates a color with custom attributes. Use for combinations not covered
// by the convenience functions below.
func New(attrs ...color.Attribute) *color.Color {
	return color.New(attrs...)
}

// -----------------------------------------------------------------------------
// Basic styles
// -----------------------------------------------------------------------------

func Bold() *color.Color   { return color.New(color.Bold) }
func Faint() *color.Color  { return color.New(color.Faint) }
func Italic() *color.Color { return color.New(color.Italic) }

// -----------------------------------------------------------------------------
// Foreground colors
// -----------------------------------------------------------------------------

func Red() *color.Color     { return color.New(color.FgRed) }
func Green() *color.Color   { return color.New(color.FgGreen) }
func Yellow() *color.Color  { return color.New(color.FgYellow) }
func Blue() *color.Color    { return color.New(color.FgBlue) }
func Magenta() *color.Color { return color.New(color.FgMagenta) }
func Cyan() *color.Color    { return color.New(color.FgCyan) }
func White() *color.Color   { return color.New(color.FgWhite) }

// -----------------------------------------------------------------------------
// High-intensity foreground colors
// -----------------------------------------------------------------------------

func HiRed() *color.Color     { return color.New(color.FgHiRed) }
func HiGreen() *color.Color   { return color.New(color.FgHiGreen) }
func HiYellow() *color.Color  { return color.New(color.FgHiYellow) }
func HiBlue() *color.Color    { return color.New(color.FgHiBlue) }
func HiMagenta() *color.Color { return color.New(color.FgHiMagenta) }
func HiCyan() *color.Color    { return color.New(color.FgHiCyan) }
func HiWhite() *color.Color   { return color.New(color.FgHiWhite) }

// -----------------------------------------------------------------------------
// Bold + foreground combinations
// -----------------------------------------------------------------------------

func BoldRed() *color.Color     { return color.New(color.Bold, color.FgRed) }
func BoldGreen() *color.Color   { return color.New(color.Bold, color.FgGreen) }
func BoldYellow() *color.Color  { return color.New(color.Bold, color.FgYellow) }
func BoldBlue() *color.Color    { return color.New(color.Bold, color.FgBlue) }
func BoldMagenta() *color.Color { return color.New(color.Bold, color.FgMagenta) }
func BoldCyan() *color.Color    { return color.New(color.Bold, color.FgCyan) }
func BoldWhite() *color.Color   { return color.New(color.Bold, color.FgWhite) }

func BoldHiRed() *color.Color     { return color.New(color.Bold, color.FgHiRed) }
func BoldHiGreen() *color.Color   { return color.New(color.Bold, color.FgHiGreen) }
func BoldHiYellow() *color.Color  { return color.New(color.Bold, color.FgHiYellow) }
func BoldHiBlue() *color.Color    { return color.New(color.Bold, color.FgHiBlue) }
func BoldHiMagenta() *color.Color { return color.New(color.Bold, color.FgHiMagenta) }
func BoldHiCyan() *color.Color    { return color.New(color.Bold, color.FgHiCyan) }
func BoldHiWhite() *color.Color   { return color.New(color.Bold, color.FgHiWhite) }

// -----------------------------------------------------------------------------
// Faint + foreground combinations
// -----------------------------------------------------------------------------

func FaintRed() *color.Color     { return color.New(color.Faint, color.FgRed) }
func FaintGreen() *color.Color   { return color.New(color.Faint, color.FgGreen) }
func FaintYellow() *color.Color  { return color.New(color.Faint, color.FgYellow) }
func FaintBlue() *color.Color    { return color.New(color.Faint, color.FgBlue) }
func FaintMagenta() *color.Color { return color.New(color.Faint, color.FgMagenta) }
func FaintCyan() *color.Color    { return color.New(color.Faint, color.FgCyan) }
func FaintWhite() *color.Color   { return color.New(color.Faint, color.FgWhite) }

func FaintHiRed() *color.Color     { return color.New(color.Faint, color.FgHiRed) }
func FaintHiGreen() *color.Color   { return color.New(color.Faint, color.FgHiGreen) }
func FaintHiYellow() *color.Color  { return color.New(color.Faint, color.FgHiYellow) }
func FaintHiBlue() *color.Color    { return color.New(color.Faint, color.FgHiBlue) }
func FaintHiMagenta() *color.Color { return color.New(color.Faint, color.FgHiMagenta) }
func FaintHiCyan() *color.Color    { return color.New(color.Faint, color.FgHiCyan) }
func FaintHiWhite() *color.Color   { return color.New(color.Faint, color.FgHiWhite) }

// -----------------------------------------------------------------------------
// Italic combinations
// -----------------------------------------------------------------------------

func ItalicFaint() *color.Color      { return color.New(color.Italic, color.Faint) }
func ItalicFaintWhite() *color.Color { return color.New(color.Italic, color.Faint, color.FgWhite) }
func ItalicBoldHiYellow() *color.Color {
	return color.New(color.Italic, color.Bold, color.FgHiYellow)
}

// -----------------------------------------------------------------------------
// Background combinations
// -----------------------------------------------------------------------------

func BoldBlackOnHiWhite() *color.Color {
	return color.New(color.Bold, color.FgBlack, color.BgHiWhite)
}

func BoldOnHiYellow() *color.Color {
	return color.New(color.Bold, color.BgHiYellow)
}
