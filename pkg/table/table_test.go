package table

import (
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/viper"
)

func TestBubbleTableStaticOutputHasNoANSI(t *testing.T) {
	table := NewBubbleTable([]string{"Name"}, true)
	table.SetData([][]string{{"Example"}})

	if output := table.RenderStatic(); strings.Contains(output, "\x1b[") {
		t.Fatalf("static table output contains ANSI escapes: %q", output)
	}
}

func TestTableRenderRespectsColorPolicy(t *testing.T) {
	previousNoColor := color.NoColor
	previousSetting := viper.Get("no-color")
	t.Cleanup(func() {
		color.NoColor = previousNoColor
		viper.Set("no-color", previousSetting)
	})
	for _, tt := range []struct {
		name       string
		noColor    bool
		redirected bool
	}{
		{name: "terminal"},
		{name: "no-color", noColor: true},
		{name: "pipe", redirected: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			color.NoColor = tt.redirected
			viper.Set("no-color", tt.noColor)
			for _, table := range []*Table{NewPlainTable(), NewStyledTable()} {
				table.SetHeaders([]string{"Name"})
				table.AppendRow([]string{"Example"})
				out := table.Render()
				wantANSI := !tt.noColor && !tt.redirected
				if gotANSI := strings.Contains(out, "\x1b"); gotANSI != wantANSI {
					t.Errorf("ANSI = %t, want %t: %q", gotANSI, wantANSI, out)
				}
				if !strings.Contains(out, "Name") || !strings.Contains(out, "Example") {
					t.Errorf("table content missing: %q", out)
				}
			}
		})
	}
}
