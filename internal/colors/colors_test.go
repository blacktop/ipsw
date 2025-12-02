package colors

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestInit_ForceOn(t *testing.T) {
	// Save and restore original state
	orig := color.NoColor
	defer func() { color.NoColor = orig }()

	color.NoColor = true // start disabled
	forceOn := true
	Init(&forceOn)

	if color.NoColor {
		t.Error("expected colors enabled when Init(true)")
	}
	if !Enabled() {
		t.Error("Enabled() should return true")
	}
}

func TestInit_ForceOff(t *testing.T) {
	orig := color.NoColor
	defer func() { color.NoColor = orig }()

	color.NoColor = false // start enabled
	forceOff := false
	Init(&forceOff)

	if !color.NoColor {
		t.Error("expected colors disabled when Init(false)")
	}
	if Enabled() {
		t.Error("Enabled() should return false")
	}
}

func TestInit_Nil_KeepsExisting(t *testing.T) {
	orig := color.NoColor
	defer func() { color.NoColor = orig }()

	// Test with colors enabled
	color.NoColor = false
	Init(nil)
	if color.NoColor {
		t.Error("Init(nil) should not change NoColor when it was false")
	}

	// Test with colors disabled
	color.NoColor = true
	Init(nil)
	if !color.NoColor {
		t.Error("Init(nil) should not change NoColor when it was true")
	}
}

func TestColorOutput_Enabled(t *testing.T) {
	orig := color.NoColor
	defer func() { color.NoColor = orig }()

	color.NoColor = false

	result := Bold().Sprint("test")
	if !strings.Contains(result, "\x1b[") {
		t.Errorf("expected ANSI codes when colors enabled, got: %q", result)
	}
}

func TestColorOutput_Disabled(t *testing.T) {
	orig := color.NoColor
	defer func() { color.NoColor = orig }()

	color.NoColor = true

	result := Bold().Sprint("test")
	if strings.Contains(result, "\x1b[") {
		t.Errorf("expected no ANSI codes when colors disabled, got: %q", result)
	}
	if result != "test" {
		t.Errorf("expected plain 'test', got: %q", result)
	}
}

func TestAllConstructors(t *testing.T) {
	orig := color.NoColor
	defer func() { color.NoColor = orig }()

	color.NoColor = false

	// Just verify they don't panic and return non-nil
	constructors := []struct {
		name string
		fn   func() *color.Color
	}{
		{"Bold", Bold},
		{"Faint", Faint},
		{"Italic", Italic},
		{"Red", Red},
		{"Green", Green},
		{"Yellow", Yellow},
		{"Blue", Blue},
		{"Magenta", Magenta},
		{"Cyan", Cyan},
		{"White", White},
		{"HiRed", HiRed},
		{"HiGreen", HiGreen},
		{"HiYellow", HiYellow},
		{"HiBlue", HiBlue},
		{"HiMagenta", HiMagenta},
		{"HiCyan", HiCyan},
		{"HiWhite", HiWhite},
		{"BoldRed", BoldRed},
		{"BoldGreen", BoldGreen},
		{"BoldYellow", BoldYellow},
		{"BoldBlue", BoldBlue},
		{"BoldMagenta", BoldMagenta},
		{"BoldCyan", BoldCyan},
		{"BoldWhite", BoldWhite},
		{"BoldHiRed", BoldHiRed},
		{"BoldHiGreen", BoldHiGreen},
		{"BoldHiYellow", BoldHiYellow},
		{"BoldHiBlue", BoldHiBlue},
		{"BoldHiMagenta", BoldHiMagenta},
		{"BoldHiCyan", BoldHiCyan},
		{"BoldHiWhite", BoldHiWhite},
		{"FaintRed", FaintRed},
		{"FaintGreen", FaintGreen},
		{"FaintYellow", FaintYellow},
		{"FaintBlue", FaintBlue},
		{"FaintMagenta", FaintMagenta},
		{"FaintCyan", FaintCyan},
		{"FaintWhite", FaintWhite},
		{"FaintHiRed", FaintHiRed},
		{"FaintHiGreen", FaintHiGreen},
		{"FaintHiYellow", FaintHiYellow},
		{"FaintHiBlue", FaintHiBlue},
		{"FaintHiMagenta", FaintHiMagenta},
		{"FaintHiCyan", FaintHiCyan},
		{"FaintHiWhite", FaintHiWhite},
		{"ItalicFaint", ItalicFaint},
		{"ItalicFaintWhite", ItalicFaintWhite},
		{"ItalicBoldHiYellow", ItalicBoldHiYellow},
		{"BoldBlackOnHiWhite", BoldBlackOnHiWhite},
		{"BoldOnHiYellow", BoldOnHiYellow},
	}

	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.fn()
			if c == nil {
				t.Errorf("%s() returned nil", tc.name)
				return
			}
			result := c.Sprint("x")
			if result == "" {
				t.Errorf("%s().Sprint() returned empty", tc.name)
			}
		})
	}
}

func TestNew(t *testing.T) {
	orig := color.NoColor
	defer func() { color.NoColor = orig }()

	color.NoColor = false

	c := New(color.Bold, color.FgRed, color.BgWhite)
	if c == nil {
		t.Fatal("New() returned nil")
	}

	result := c.Sprint("test")
	if !strings.Contains(result, "\x1b[") {
		t.Errorf("New() color should produce ANSI codes, got: %q", result)
	}
}
