package table

import (
	"strings"
	"testing"
)

func TestBubbleTableStaticOutputHasNoANSI(t *testing.T) {
	table := NewBubbleTable([]string{"Name"}, true)
	table.SetData([][]string{{"Example"}})

	if output := table.RenderStatic(); strings.Contains(output, "\x1b[") {
		t.Fatalf("static table output contains ANSI escapes: %q", output)
	}
}
