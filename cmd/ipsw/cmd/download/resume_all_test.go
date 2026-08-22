package download

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestLegacyResumeAllFlagRemoved(t *testing.T) {
	commands := []*cobra.Command{
		downloadIpswCmd,
		downloadDevCmd,
		downloadOtaCmd,
		downloadWikiCmd,
		downloadPccCmd,
		downloadAppledbCmd,
		downloadKdkCmd,
		downloadXcodeCmd,
		downloadMacosCmd,
	}
	for _, command := range commands {
		if flag := command.Flags().Lookup("resume-all"); flag != nil {
			t.Errorf("%s still exposes removed --resume-all flag", command.CommandPath())
		}
	}
}
