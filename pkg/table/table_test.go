package table

import (
	"fmt"
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

func TestBubbleTableStaticOutputIncludesEveryRow(t *testing.T) {
	table := NewBubbleTable([]string{"Name"}, false)
	var data [][]string
	for i := range 200 {
		data = append(data, []string{fmt.Sprintf("row-%03d", i)})
	}
	table.SetData(data)

	output := table.RenderStatic()
	for _, want := range []string{"row-000", "row-199"} {
		if !strings.Contains(output, want) {
			t.Fatalf("static table output is missing %q:\n%s", want, output)
		}
	}
	if got := strings.Count(output, "row-"); got != len(data) {
		t.Fatalf("static table output has %d rows, want %d", got, len(data))
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
