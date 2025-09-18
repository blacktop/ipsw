package cpp

import (
	"fmt"
	"strings"

	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/fatih/color"
)

var (
	colorClass    = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
	colorBundle   = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	colorAddr     = color.New(color.Faint).SprintfFunc()
	colorMethod   = color.New(color.FgHiCyan).SprintFunc()
	colorOverride = color.New(color.FgYellow).SprintFunc()
	colorNew      = color.New(color.FgHiGreen).SprintFunc()
)

// String returns a formatted string representation of the ClassMeta
func (c *ClassMeta) String() string {
	var b strings.Builder
	var cMethod string
	if len(c.Methods) > 0 {
		cMethod = fmt.Sprintf(" (%03d meths)", len(c.Methods))
	}
	b.WriteString(fmt.Sprintf("init=%s size=%s meta=%s vtab=%s%s",
		colorAddr("%#x", c.AllocFunc),
		colorAddr("%#03x", c.Size),
		colorAddr("%#x", c.MetaPtr),
		colorAddr("%#x", c.VtableAddr),
		cMethod))
	if c.SuperMeta != 0 {
		b.WriteString(fmt.Sprintf(" parent=%s", colorAddr("%#x", c.SuperMeta)))
	}
	b.WriteString(fmt.Sprintf(" %s", colorClass(c.Name)))
	if c.Bundle != "" {
		b.WriteString(fmt.Sprintf(" (%s)", colorBundle(c.Bundle)))
	}
	return b.String()
}

// String returns a formatted string representation of the MethodInfo
func (m *MethodInfo) String() string {
	offset := fmt.Sprintf("%#x", m.Index*8)
	funcAddr := colorAddr("%#x", m.Address)
	var extra strings.Builder
	if m.OverrideOf != 0 {
		extra.WriteString(fmt.Sprintf(" overrides=%s", colorAddr("%#x", m.OverrideOf)))
	} else {
		extra.WriteString(" overrides=0x0000000000000000")
	}
	if m.PAC != 0 {
		extra.WriteString(fmt.Sprintf(" pac=0x%04x", m.PAC))
	}
	methodName := demangle.Do(m.Name, false, true)
	if m.OverrideOf != 0 {
		methodName = colorOverride(methodName)
	} else {
		methodName = colorNew(methodName)
	}
	return fmt.Sprintf("    %6s func=%s%s %s", offset, funcAddr, extra.String(), methodName)
}
