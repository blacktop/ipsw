package cmd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/pkg/info"
	"github.com/spf13/cobra"
)

func TestDeviceHintNamesExtractionSelector(t *testing.T) {
	for _, selector := range []string{"device", "extract-device", ""} {
		cmd := &cobra.Command{Use: "synthetic"}
		if selector != "" {
			cmd.Flags().String(selector, "", "selector")
		}
		if selector == "extract-device" {
			cmd.Flags().String("device", "", "feed filter")
		}
		err := withDeviceSelectionHint(cmd, fmt.Errorf("scan: %w", info.ErrAmbiguousSystemOS))
		if !errors.Is(err, info.ErrAmbiguousSystemOS) {
			t.Fatal("lost error identity")
		}
		if selector == "" {
			if strings.Contains(err.Error(), "use --") {
				t.Fatal("hint named an unavailable flag")
			}
		} else if !strings.Contains(err.Error(), "use --"+selector) {
			t.Fatalf("wrong selector hint: %v", err)
		}
	}
}
