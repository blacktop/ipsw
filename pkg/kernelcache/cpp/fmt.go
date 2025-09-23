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
func (c *Class) String() string {
	var b strings.Builder
	// Use DiscoveryPC (BL call site) to match iometa's behavior
	// Note: Ctor is the function start, DiscoveryPC is where the BL to OSMetaClass occurs
	initAddr := c.DiscoveryPC
	if initAddr == 0 {
		initAddr = c.Ctor // Fallback to function start if DiscoveryPC not set
	}
	b.WriteString(fmt.Sprintf("init=%s size=%s",
		colorAddr("%#x", initAddr),
		colorAddr("%#04x", c.Size)))
	if c.SuperMeta != 0 {
		b.WriteString(fmt.Sprintf(" parent=%s", colorAddr("%#x", c.SuperMeta)))
	}
	if c.MetaPtr != 0 {
		b.WriteString(fmt.Sprintf(" meta=%s", colorAddr("%#x", c.MetaPtr)))
	}
	if c.VtableAddr != 0 {
		b.WriteString(fmt.Sprintf(" vtab=%s", colorAddr("%#x", c.VtableAddr)))
	}
	if len(c.Methods) > 0 {
		b.WriteString(fmt.Sprintf(" (%03d meths)", len(c.Methods)))
	}
	b.WriteString(fmt.Sprintf(" %s", colorClass(c.Name)))
	if c.Bundle != "" {
		b.WriteString(fmt.Sprintf("\t(%s)", colorBundle(c.Bundle)))
	}
	if len(c.Methods) > 0 {
		b.WriteString("\n")
		for _, m := range c.Methods {
			b.WriteString(m.String())
			b.WriteString("\n")
		}
	}
	return b.String()
}

// String returns a formatted string representation of the MethodInfo
func (m *Method) String() string {
	offset := fmt.Sprintf("%#x", m.Index)
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
