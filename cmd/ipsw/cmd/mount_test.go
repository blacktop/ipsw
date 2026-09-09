package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/info"
	"golang.org/x/term"
)

func TestSelectMountSystemOSNonInteractive(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())) {
		t.Skip("requires non-interactive input or error output")
	}
	_, err := selectMountSystemOS([]info.SystemOSDMG{
		{Path: "common.dmg.aea", Devices: []string{"Mac99,1", "Mac99,2", "Mac99,3"}},
		{Path: "special.dmg.aea", Devices: []string{"Mac99,4"}},
		{Path: "board.dmg.aea", Boards: []string{"j991ap"}},
	})
	if err == nil {
		t.Fatal("ambiguous non-interactive selection succeeded")
	}
	for _, want := range []string{"--device", "common.dmg.aea [Mac99,1, Mac99,2, Mac99,3]", "special.dmg.aea [Mac99,4]", "board.dmg.aea [j991ap]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}
